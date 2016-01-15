#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ev.h>
#include <arpa/inet.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>
#include "http_parser.h"

#define PORT_NO 3128
#define BUFFER_SIZE 1<<24

#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
(type *)( (char *)__mptr - offsetof(type,member) );})

#ifdef DEBUG
# define DEBUG_PRINT printf
#else
# define DEBUG_PRINT
#endif

extern const char* method_strings[];

struct proxy_watcher{
	ev_io client_watcher;
	ev_io server_watcher;
	http_parser parser;
	int upgrade;
};

int total_clients = 0;  // Total number of connected clients

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void server_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void client_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

http_parser_settings settings;
char buffer[BUFFER_SIZE];

int send_str(int sockfd, const char* buf, int flags){
	return send(sockfd, buf,strlen(buf),flags);
}

int message_begin_cb (http_parser *p)
{
	struct proxy_watcher *proxy = container_of(p,struct proxy_watcher,parser);
	//send_str(proxy->server_watcher.fd, "\r\n",0);
	send_str(proxy->server_watcher.fd, method_strings[p->method],MSG_MORE);
	DEBUG_PRINT("%s %d\n",method_strings[p->method],strlen(method_strings[p->method]));
	return 0;
}


int url_cb (http_parser *p, const char *buf, size_t len){
	struct proxy_watcher *proxy = container_of(p,struct proxy_watcher,parser);
	
	send_str(proxy->server_watcher.fd, " ",MSG_MORE);
	send(proxy->server_watcher.fd, buf,len,MSG_MORE);
	send_str(proxy->server_watcher.fd, " ",MSG_MORE);
	send_str(proxy->server_watcher.fd, "HTTP/1.1\r\n",0);
	DEBUG_PRINT("url_cb %.*s\n",len,buf);
	return 0;
}

int header_field_cb (http_parser *p, const char *buf, size_t len){
	struct proxy_watcher *proxy = container_of(p,struct proxy_watcher,parser);
	send(proxy->server_watcher.fd, buf,len,MSG_MORE);
	send_str(proxy->server_watcher.fd, ": ",MSG_MORE);
	DEBUG_PRINT("header_field_cb %.*s\n",len,buf);
	return 0;
}

int header_value_cb (http_parser *p, const char *buf, size_t len){
	struct proxy_watcher *proxy = container_of(p,struct proxy_watcher,parser);
	send(proxy->server_watcher.fd,buf,len,MSG_MORE);
	send_str(proxy->server_watcher.fd, "\r\n",MSG_MORE);
	DEBUG_PRINT("header_value_cb %.*s\n",len,buf);
	return 0;
}

int headers_complete_cb (http_parser *p)
{
	struct proxy_watcher *proxy = container_of(p,struct proxy_watcher,parser);
	send_str(proxy->server_watcher.fd, "\r\n",MSG_MORE);
	DEBUG_PRINT("headers_complete_cb\n");
	return 0;
}

int chunk_header_cb (http_parser *p)
{
	struct proxy_watcher *proxy = container_of(p,struct proxy_watcher,parser);
	char hex[64];
	sprintf(hex,"%llx\r\n",p->content_length);
	send_str(proxy->server_watcher.fd, hex,MSG_MORE);
	return 0;
}

int body_cb (http_parser *p, const char *buf, size_t len){
	struct proxy_watcher *proxy = container_of(p,struct proxy_watcher,parser);
	send(proxy->server_watcher.fd,buf,len,0);
	return 0;
}

void http_parser_setting(){
/*
  http_cb      on_message_begin;
  http_data_cb on_url;
  http_data_cb on_status;
  http_data_cb on_header_field;
  http_data_cb on_header_value;
  http_cb      on_headers_complete;
  http_data_cb on_body;
  http_cb      on_message_complete;
  http_cb      on_chunk_header;
  http_cb      on_chunk_complete;
*/
 
	settings.on_message_begin = message_begin_cb;
	settings.on_url = url_cb;
	settings.on_header_field = header_field_cb;
	settings.on_header_value = header_value_cb;
	settings.on_headers_complete = headers_complete_cb;
	settings.on_chunk_header = chunk_header_cb;
	settings.on_body = body_cb;
	
}



int main()
{
	struct ev_loop *loop = ev_default_loop(0);
	int sd;
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);
	struct ev_io w_accept;
	int bf=1;
	
	// Create server socket
	if( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
	{
		perror("socket error");
		return -1;
	}
	
	if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &bf, sizeof(bf)) <0){
		perror("cannot reuse address");
		return -1;
	}

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT_NO);
	addr.sin_addr.s_addr = INADDR_ANY;
	// Bind socket to address
	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0)
	{
		perror("bind error");
	}

	// Start listing on the socket
	if (listen(sd, 2) < 0)
	{
		perror("listen error");
		return -1;
	}

	// Initialize and start a watcher to accepts client requests
	ev_io_init(&w_accept, accept_cb, sd, EV_READ);
	ev_io_start(loop, &w_accept);

	http_parser_setting();
	
	// Start infinite loop
	while (1)
	{
		printf("listening ....\n");
		ev_loop(loop, 0);
	}

	return 0;
}

void close_proxy(struct ev_loop *loop, struct proxy_watcher *proxy){
	ev_io_stop(loop,&proxy->client_watcher);
	ev_io_stop(loop,&proxy->server_watcher);
	close(proxy->client_watcher.fd);
	close(proxy->server_watcher.fd);
	free(proxy);
	DEBUG_PRINT("peer might closing");
	total_clients --; // Decrement total_clients count
}

/* Accept client requests */
void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct sockaddr_in client_addr,server_addr;
	socklen_t client_len = sizeof(client_addr);
	socklen_t server_len = sizeof(server_addr);
	int client_sd,server_sd;
	struct proxy_watcher *proxy;
	char DEST_IP[BUFFER_SIZE];
	int nodelay=1;
	

	DEBUG_PRINT("new connection!\n");
	
	if(EV_ERROR & revents)
	{
		perror("got invalid event");
		return;
	}
	

	

	// Accept client request
	client_sd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);

	if (client_sd < 0)
	{
		perror("accept error");
		return;
	}

	total_clients ++; // Increment total_clients count
	DEBUG_PRINT("Successfully connected with client.\n");
	DEBUG_PRINT("%d client(s) connected.\n", total_clients);

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(80);
	if(getsockopt(client_sd, SOL_IP, SO_ORIGINAL_DST, &server_addr, &server_len) < 0){
		perror("cannot get original destination");
		return;
	}
	
	//strlcpy (DEST_IP, inet_ntoa (server_addr.sin_addr), 17);
	//printf("%s\n", DEST_IP);
	
	server_sd=socket( PF_INET, SOCK_STREAM, 0);
	setsockopt(server_sd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(int));
	
	if(server_sd <0){
		perror("socket error");
		return;
	}
	
	if(connect(server_sd, (struct sockaddr*)&server_addr, sizeof(server_addr))<0)
	{
	   perror("server socket connect error");
	   return;
	}
	
	proxy = (struct proxy_watcher*) malloc (sizeof(struct proxy_watcher));
	proxy->upgrade = 0;
	http_parser_init(&proxy->parser, HTTP_REQUEST);
	
	
	ev_io_init(&proxy->server_watcher, server_read_cb, server_sd, EV_READ);
	ev_io_start(loop, &proxy->server_watcher);
	
	// Initialize and start watcher to read client requests
	ev_io_init(&proxy->client_watcher, client_read_cb, client_sd, EV_READ);
	ev_io_start(loop, &proxy->client_watcher);
}


void server_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents){
	ssize_t read;
	struct proxy_watcher *proxy = container_of(watcher,struct proxy_watcher,server_watcher);

	if(EV_ERROR & revents)
	{
		perror("got invalid event");
		return;
	}

	// Receive message from client socket
	read = recv(watcher->fd, buffer, BUFFER_SIZE, 0);

	if(read < 0)
	{
		close_proxy(loop,proxy);
		perror("read error");
		return;
	}

	if(read == 0)
	{
		// Stop and free watchet if client socket is closing
		close_proxy(loop,proxy);
		return;
	}
	else
	{
		//send back to client
		send(proxy->client_watcher.fd, buffer,read,0);
		//printf("message:%s\n",buffer);
	}
}

/* Read client message */
void client_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents){
	ssize_t read;
	struct proxy_watcher *proxy = container_of(watcher,struct proxy_watcher,client_watcher);

	if(EV_ERROR & revents)
	{
		perror("got invalid event");
		return;
	}

	// Receive message from client socket
	read = recv(watcher->fd, buffer, BUFFER_SIZE, 0);

	if(read < 0)
	{
		close_proxy(loop,proxy);
		perror("read error");
		return;
	}

	if(read == 0)
	{
		// Stop and free watchet if client socket is closing
		close_proxy(loop,proxy);
		return;
	}
	else
	{
		
		if(proxy->upgrade==0){
			int nparsed=http_parser_execute(&proxy->parser,&settings, buffer,read);
			DEBUG_PRINT("readed %d parsed %d\n", read,nparsed);
			if(proxy->parser.upgrade){
				proxy->upgrade=1;
			}else if(nparsed != read){
				DEBUG_PRINT("parsing error!\nclose connection!\n");
				close_proxy(loop,proxy);
				return;
			}
		}else{
			//send back to server
			send(proxy->server_watcher.fd, buffer,read, 0);
		}
	}
}