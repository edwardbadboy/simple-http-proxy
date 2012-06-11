#include "simple_proxy_http.h"

#ifdef WIN32
	WSADATA wsaData;
#endif
PSOCK G_my_sock=0;
gint G_my_port=0;
SOCKLEN_T G_sin_size=0;
struct sockaddr_in G_my_addr;
#ifndef WIN32
	struct sigaction G_sa;
#endif

typedef int (*serve_function_p)(p_proxy_sock proxy);
serve_function_p serve_client_funs[]={serve_client_header, serve_client_body};

serve_function_p serve_server_funs[]={serve_server_header, serve_server_body};


int main(int argc, char* argv[])
{
	if(setup_sockets(argc,argv) != 0){
		fprintf(stderr,"ERROR: Failed to initialize thread support or network!\n");
		return -1;
	}

	return do_monitor();
}


gint setup_sockets(int argc, char* argv[])
{
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char ipstr[INET6_ADDRSTRLEN]={0};
	void* addr=NULL;
	struct sockaddr_in *ipv4=NULL;
	struct sockaddr_in6 *ipv6=NULL;
	#ifdef WIN32
		gint iresult=0;
	#endif
	gint gsockflag=1;
	
	if(argc!=2){
		fprintf(stderr,"Usage: simple_proxy_http bind_port\n");
		return -1;
	}

	if(sscanf(argv[1],"%d",&G_my_port)!=1){
		fprintf(stderr,"Usage: simple_proxy_http bind_port\n");
	}

	#ifndef G_THREADS_ENABLED
		return -1;
	#endif
	if(!g_thread_supported()){
		g_thread_init(NULL);
	}

	#ifdef WIN32
	iresult = WSAStartup( MAKEWORD(2,2), &wsaData );
	if(-1==iresult){
		return -1;
	}
	#endif

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	//hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	rv = getaddrinfo(NULL, argv[1], &hints, &servinfo);
	if(rv!=0){
		fprintf(stderr, "ERROR: getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((G_my_sock = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == INVALID_SOCKET) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(G_my_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&gsockflag,sizeof(gsockflag)) != 0) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(G_my_sock, p->ai_addr, p->ai_addrlen) != 0) {
#ifdef WIN32
			closesocket(G_my_sock);
#else
			close(G_my_sock);
#endif
			perror("server: bind");
			continue;
		}

#ifdef WIN32
		if(p->ai_family==AF_INET){
			int sl=sizeof(ipstr),ret=0;
			ret=WSAAddressToStringA(p->ai_addr,p->ai_addrlen,NULL,ipstr,&sl);
			fprintf(stderr,"INFO: Server binded at address %s\n",ipstr);
		}else{
			int sl=sizeof(ipstr),ret=0;
			ret=WSAAddressToStringA(p->ai_addr,p->ai_addrlen,NULL,ipstr,&sl);
			fprintf(stderr,"INFO: Server binded at address %s\n",ipstr);
		}
#else
		if(p->ai_family==AF_INET){
			ipv4=(struct sockaddr_in *)p->ai_addr;
			addr=&(ipv4->sin_addr);
		}else if(p->ai_family==AF_INET6){
			ipv6=(struct sockaddr_in6 *)p->ai_addr;
			addr=&(ipv6->sin6_addr);
		}else{
			fprintf(stderr,"INFO: Server binded at an address that is neither ipv4 nor ipv6\n");
			break;
		}

		inet_ntop(p->ai_family,addr,ipstr,sizeof(ipstr));

		fprintf(stderr,"INFO: Server binded at address %s:%s\n",ipstr,argv[1]);
#endif
		break;
	}

	freeaddrinfo(servinfo);

	if (p == NULL)  {
		fprintf(stderr, "ERROR: Server failed to bind\n");
		return 2;
	}

#ifndef WIN32
	sigemptyset(&G_sa.sa_mask);
	G_sa.sa_flags=0;
	G_sa.sa_handler = SIG_IGN; 
	if(sigaction( SIGPIPE, &G_sa, 0 )<0){
		fprintf(stderr,"ERROR: Failed to install SIGPIPE signal handler\n");
		return -1;
	}
#endif

	return 0;
}


void endpoint_status_init(endpoint_status *st){
	st->sock = INVALID_SOCKET;
	st->r_transfer_mode = HTTP_HEADER;
	st->content_len = -1;
	st->http_ver = HTTP10;
}


p_proxy_sock proxy_new(){
	p_proxy_sock proxy = NULL;
	proxy=(p_proxy_sock)g_try_malloc0(sizeof(*proxy));
	if(proxy == NULL){
		return NULL;
	}
	endpoint_status_init(&(proxy->c));
	endpoint_status_init(&(proxy->s));
	proxy->ishttps = FALSE;
	proxy->persistent_conn = FALSE;
	return proxy;
}


gint do_monitor()
{
	p_proxy_sock proxy=NULL;
	void *addr=NULL;
	struct sockaddr_in * ipv4=NULL;
	struct sockaddr_in6 * ipv6=NULL;
	char ports[10]={0};
	char ipstr[INET6_ADDRSTRLEN]={0};

	if (listen(G_my_sock, 300) != 0){
		/* 如果调用listen 失败,则给出错误提示,退出 */
		perror("listen");
		exit(-1);
	}

	while(1){
		proxy = proxy_new();
		if(proxy == NULL){
			g_usleep(1000000l);
			continue;
		}
		G_sin_size = sizeof(struct sockaddr_storage);
		if ((proxy->c.sock = accept(G_my_sock, (struct sockaddr *)&(proxy->c.addr), &G_sin_size)) == -1){
			/* 如果调用accept()出现错误,则给出错误提 */
			perror("accept");
			g_free(proxy);
		}
#ifdef WIN32
		if(proxy->c.addr.ss_family==AF_INET){
			int sl=sizeof(ipstr),ret=0;
			ret=WSAAddressToStringA((struct sockaddr*)&(proxy->c.addr),sizeof(proxy->c.addr),NULL,ipstr,&sl);
			fprintf(stderr,"INFO: Accepted client connection from %s\n",ipstr);
		}else{
			int sl=sizeof(ipstr),ret=0;
			ret=WSAAddressToStringA((struct sockaddr*)&(proxy->c.addr),sizeof(proxy->c.addr),NULL,ipstr,&sl);
			fprintf(stderr,"INFO: Accepted client connection from %s\n",ipstr);
		}
#else
		addr=NULL;
		if(proxy->c.addr.ss_family==AF_INET){
			ipv4=(struct sockaddr_in *)&(proxy->c.addr);
			addr=&(ipv4->sin_addr);
			sprintf(ports,"%d",ipv4->sin_port);
		}else if(proxy->c.addr.ss_family==AF_INET6){
			ipv6=(struct sockaddr_in6 *)&(proxy->c.addr);
			addr=&(ipv6->sin6_addr);
			sprintf(ports,"%d",ipv6->sin6_port);
		}else{
			fprintf(stderr,"INFO: Accepted client that is neither ipv4 nor ipv6\n");
		}
		if(addr!=NULL){
			inet_ntop(proxy->c.addr.ss_family,addr,ipstr,sizeof(ipstr));
			fprintf(stderr,"INFO: Accepted client connection from [%s]:%s\n",ipstr,ports);
		}
#endif
		proxy->c.t = g_thread_create(serve_client, proxy, FALSE, NULL);
		if(NULL == proxy->c.t){
			fprintf(stderr,"ERROR: Can not create thread for handling new connections!\n");
#ifdef WIN32
			closesocket(proxy->c.sock);
#else
			close(proxy->c.sock);
#endif
			g_free(proxy);
			g_usleep(10000l);
		}
	}
	return 0;
}


gpointer serve_client(gpointer data){
	p_proxy_sock proxy=NULL;

	if((proxy = (p_proxy_sock)data) == NULL){
		return NULL;
	}
#ifdef WIN32
	proxy->c.gch = g_io_channel_win32_new_socket(proxy->c.sock);
#else
	proxy->c.gch = g_io_channel_unix_new(proxy->c.sock);
#endif
	if(!proxy->c.gch){
		fprintf(stderr, "ERROR: error create giochannel\n");
		g_free(proxy);
		return NULL;
	}
	g_io_channel_set_encoding(proxy->c.gch, NULL, NULL);
	/*g_io_channel_set_buffered(proxy->c.gch, FALSE);*/
	g_io_channel_set_line_term(proxy->c.gch, "\r\n", -1);

	while(serve_client_funs[proxy->c.r_transfer_mode](proxy)!=-1){
		;
	}

	fprintf(stderr, "INFO: Client closes connection\n");

	shutdown(proxy->s.sock,SHUT_WR);
	g_io_channel_get_flags(proxy->s.gch);
	shutdown(proxy->c.sock,SHUT_RD);
	g_io_channel_get_flags(proxy->c.gch);
	g_usleep(1000000);
	if(proxy->s.t){
		g_thread_join(proxy->s.t);
		fprintf(stderr, "DEBUG: Server thread ended\n");
	}
	handle_client_connect_error_clean(proxy);

	fprintf(stderr, "DEBUG: Client thread ended\n");
	return NULL;
}


static gboolean https_detect(const gchar *line, gsize line_len){
	const gchar *connect_tok = g_strstr_len(line, line_len, "CONNECT ");
	if(connect_tok == NULL){
		return FALSE;
	}
	return TRUE;
}


static int http_version_detect(const gchar *line, gsize line_len, http_version *ver){
	const gchar *verstr = NULL;
	//do not use g_str_has_suffix, not safe
	verstr = g_strstr_len(line, line_len, "HTTP/1.0\r\n");
	if(verstr){
		*ver = HTTP10;
		return 1;
	}
	verstr = g_strstr_len(line, line_len, "HTTP/1.1\r\n");
	if(verstr){
		*ver = HTTP11;
		return 1;
	}
	return -1;
}


static int http_persistent_connection_detect(const gchar *line, gsize line_len, gboolean *persist){
#ifdef WIN32
#define strncasecmp _strnicmp
#endif
	if(strncasecmp(line, "Connection: close\r\n", line_len)==0){
		*persist = FALSE;
		return 1;
	}
	if(strncasecmp(line, "Connection: keep-alive\r\n", line_len)==0){
		*persist = TRUE;
		return 1;
	}
#ifdef WIN32
#undef strncasecmp
#endif
	return -1;
}


static int http_content_length_detect(const gchar *line, gsize line_len, long *len){
	const gchar *contentlenstr = NULL;
	long contentlen = 0;
	//do not use g_str_has_prefix, not safe
	contentlenstr = g_strstr_len(line, line_len, "Content-Length: ");
	if(!contentlenstr){
		return -1;
	}
	contentlenstr += 16;  //16 = strlen("Content-Length: ")
	if(1 != sscanf(contentlenstr, "%ld", &contentlen)){
		fprintf(stderr, "INFO: bad content-length header: %s", line);
		return -1;
	}
	*len = contentlen;
	return 1;
}


static int http_parse_ipv6_host_port_with_brackets(const char *addr, size_t addrlen,
									 char *ipadd, size_t ipadd_len, int *port){
	const char *r_bracket = NULL;
	const char *l_bracket = NULL;
	const char *port_s = NULL;
	size_t add_count = 0;

	l_bracket = g_strstr_len(addr, addrlen, "[");
	r_bracket = g_strstr_len(addr, addrlen, "]");
	if(l_bracket == NULL || r_bracket == NULL || (l_bracket >= r_bracket-1)){
		//brackets do not match, or there is no content in the bracket
		fprintf(stderr,"ERROR: found brackets in host header but bad format %s", addr);
		return -1;
	}

	//get host ip the brackets
	ipadd[0] = '\0';
	if((size_t)(r_bracket - l_bracket) > ipadd_len){
		fprintf(stderr,"ERROR: host string too long\n");
		return -1;
	}
	add_count = r_bracket - l_bracket ;
	//((r_bracket-1)-(l_bracket+1))+1=r_bracket-l_bracket-1
	strncpy(ipadd , l_bracket+1 , add_count);
	ipadd[add_count] = '\0';

	port_s=strstr(r_bracket,":");
	if(port_s==NULL){
		//no port in the address string
		//if an ipv6 address is like [xx:xx:xx]:8080
		//it must contains a port, otherwise the brackets are useless
		//so if it contians brackets, it should contain port
		return -1;
	}

	++port_s;
	if(sscanf(port_s, "%d", port)!=1){
		return -1;
	}

	return 1;
}


static int get_host_port_bewteen(const gchar *line, gsize line_len,
								 const gchar *prefix, const gchar *suffix,
								 gchar *host, gsize host_len, int *port, int def_port){
	const gchar *host_s = NULL;
	const gchar *host_e = NULL;
	const gchar *col_pos = NULL;
	const gchar *lbracket = NULL;
	size_t pflen = strlen(prefix);

	host_s = g_strstr_len(line, line_len, prefix);
	if(host_s == NULL){
		//not a error, just a failed try
		//the wanted prefix may appear in later headers
		return -1;
	}
	host_s += pflen;
	host_e = g_strstr_len(host_s, line_len - pflen, suffix);
	if(NULL == host_e){
		fprintf(stderr,"ERROR: Can not get \\r\\n from req\n");
		return -1;
	}
	while(*host_s && isspace(*host_s)){
		++host_s;
	}
	while(host_e > host_s && isspace(*(host_e - 1))){
		--host_e;
	}
	if((gsize)(host_e - host_s) > host_len - 1){
		fprintf(stderr,"ERROR: Host string is too long: len=%ld, allow len=%lu\n",
				host_e - host_s, host_len - 1);
		return -1;
	}

	lbracket = g_strstr_len(host_s, line_len - pflen, "[");
	if(lbracket){
		//a ipv6 address contains port infomation
		return http_parse_ipv6_host_port_with_brackets(host_s, host_e - host_s,
													   host, host_len, port);
	}

	col_pos = g_strrstr_len(host_s, host_e - host_s, ":");
	if(col_pos == NULL){
		//no port information
		host[0] = '\0';
		strncpy(host, host_s, host_e - host_s);
		host[host_e - host_s] = '\0';
		*port = def_port;
		return 1;
	}

	//column may be port indicator or the column in the ipv6 address
	if(g_strrstr_len(col_pos + 1, host_e - col_pos -1, ":")){
		//a ipv6 address can contain at least 2 ":"s
		//no port information
		host[0] = '\0';
		strncpy(host, host_s, host_e - host_s);
		host[host_e - host_s] = '\0';
		*port = def_port;
		return 1;
	}
	
	host[0] = '\0';
	strncpy(host, host_s, col_pos - host_s);
	host[col_pos - host_s] = '\0';
	sscanf(col_pos + 1, "%d", port);
	return 1;
}


static int http_host_port_detect(const gchar *line, gsize line_len,
								 gchar *host, gsize host_len, int *port, int def_port){
	return get_host_port_bewteen(line, line_len, "Host: ", "\r\n", host, host_len, port, def_port);
}


static int https_host_port_detect(const gchar *line, gsize line_len, http_version httpver,
								 gchar *host, gsize host_len, int *port, int def_port){
	return get_host_port_bewteen(line, line_len, "CONNECT ",
								 httpver==HTTP10?"HTTP/1.0\r\n":"HTTP/1.1\r\n",
								 host, host_len, port, def_port);
}


//Assume clients can be HTTP/1.0 or 1.1 and all servers are HTTP/1.1 .
//When client is 1.0, proxy always sends "connection = close" in the request to server,
//even if the client say keep-alive, the proxy can override that,
//and send "connection = close" in the response to client.
//When client is http 1.1, if any of the client or server say "connection = close", then
//there is no persistent connection and pipeline,
//otherwise proxy just use the persistent connection and pipeline.
//When is HTTPS, always use persistent connection then enter body mode.
//
//Allocate a list to store header pointers, append received string to it.
//when receive a connection= header, set the proxy->persistent_conn, and do not
//append the header to the list.
//After receive all the headers, send the element in the list one by one to the server,
//and according to the persistent_conn setting, send a connection= header to the server.
//
//When receiving header from the server, do similar things
int serve_client_header(p_proxy_sock proxy){
	gchar *line=NULL;
	gsize line_len=0;
	gsize term_pos=0;
	GIOChannel *cch=proxy->c.gch;
	GIOStatus r;
	gint port = 80;
	gchar host[1024] = {0};

	fprintf(stderr, "DEBUG: client header mode\n");

	proxy->c.headers = g_ptr_array_new();
	if(proxy->c.headers == NULL){
		return -1;
	}

	//process request uri
	r = gch_readline(cch, &line, &line_len, &term_pos);
	if(r != G_IO_STATUS_NORMAL){
		if(line){
			g_free(line);
		}
		return -1;
	}

	//detect HTTP version
	proxy->ishttps = https_detect(line, line_len);
	if(-1 == http_version_detect(line, line_len, &(proxy->c.http_ver))){
		g_free(line);
		return -1;
	}
	if(HTTP10 == proxy->c.http_ver){
		proxy->persistent_conn = FALSE;
	}else{
		proxy->persistent_conn = TRUE;
	}

	//HTTPS host and port information is in the request URI
	if(proxy->ishttps){
		int re = 0;
		port = 443;
		re = https_host_port_detect(line, line_len, proxy->c.http_ver,
									host, sizeof(host), &port, port);
		if(-1 == re){
			g_free(line);
			return -1;
		}
		fprintf(stderr, "INFO: HTTPS connection\n");
		g_ptr_array_add(proxy->c.headers, (gpointer)line);
	}else{
		//modify the request URI if is http
		//then add the request URI to the headers
		gchar *new_uri = g_try_malloc0(line_len);
		if(NULL == new_uri){
			fprintf(stderr, "ERROR: out of memory\n");
			g_free(line);
			return -1;
		}
		if(transform_http_request_uri(line, line_len, new_uri) == -1){
			g_free(line);
			g_free(new_uri);
			fprintf(stderr, "ERROR: bad request uri %s", line);
			return -1;
		}
		g_free(line);
		g_ptr_array_add(proxy->c.headers, (gpointer)new_uri);
	}


	while(1){
		//process through all the headers
		r = gch_readline(cch, &line, &line_len, &term_pos);
		if(r != G_IO_STATUS_NORMAL){
			return -1;
		}

		if(!strncmp(line, "\r\n", line_len)){
			//headers over
			g_free(line);
			line = NULL;
			line_len = 0;
			break;
		}

		http_content_length_detect(line, line_len, &(proxy->c.content_len));

		//if we are https, then port is already detected in the requested uri
		//so set the existing port infor as the default port info
		http_host_port_detect(line, line_len, host, sizeof(host), &port, port);

		{
			gboolean persist = FALSE;
			if(http_persistent_connection_detect(line, line_len, &persist)){
				if(HTTP10 == proxy->c.http_ver){
					g_free(line);
					line = NULL;
					line = g_strdup("Connection: close\r\n");
					line_len = strlen("Connection: close\r\n");
				}else{
					if(!persist){
						proxy->persistent_conn = FALSE;
					}
				}
			}
		}

		g_ptr_array_add(proxy->c.headers, (gpointer)line);
	}

	/*{
		gsize len = proxy->c.headers->len;
		gsize i = 0;
		for(i = 0; i < len; ++i){
			fprintf(stderr, "DEBUG: header %s", (char*)g_ptr_array_index(proxy->c.headers, i));
		}
	}*/

	//if the remote server is not connected, then connect to it.
	if(INVALID_SOCKET == proxy->s.sock){
		proxy->s.sock = proxy_connect(host, port);
		if(INVALID_SOCKET == proxy->s.sock){
			return -1;
		}
		fprintf(stderr, "INFO: Connected to %s\n", host);
#ifdef WIN32
		proxy->s.gch = g_io_channel_win32_new_socket(proxy->s.sock);
#else
		proxy->s.gch = g_io_channel_unix_new(proxy->s.sock);
#endif
		if(proxy->s.gch == NULL){
			return -1;
		}
		g_io_channel_set_encoding(proxy->s.gch, NULL, NULL);
		/*g_io_channel_set_buffered(proxy->s.gch, FALSE);*/
		g_io_channel_set_line_term(proxy->s.gch, "\r\n", -1);
	}

	if(!proxy->ishttps){
		//send all the headers and \r\n to the server
		gsize len = proxy->c.headers->len;
		/*fprintf(stderr, "DEBUG: client header len: %lu\n", len);*/
		gsize i = 0;
		char *s = NULL;
		for(i = 0; i < len; ++i){
			s = (char*)g_ptr_array_index(proxy->c.headers, i);
			r = gch_writechars(proxy->s.gch, s, strlen(s));
			if(G_IO_STATUS_NORMAL != r){
				return -1;
			}
			/*fprintf(stderr, "DEBUG: sent client header index: %lu\n", i);*/
		}
		r = gch_writechars(proxy->s.gch, "\r\n", 2);
		if(G_IO_STATUS_NORMAL != r){
			return -1;
		}
		/*r = gch_flush(proxy->s.gch);
		if(G_IO_STATUS_NORMAL != r){
			return -1;
		}*/
		/*fprintf(stderr, "DEBUG: sent client header over\n");*/
	}

	//free the headers and goto http body handling mode,
	g_ptr_array_free(proxy->c.headers, TRUE);
	g_ptr_array_unref(proxy->c.headers);
	proxy->c.headers = NULL;
	proxy->c.r_transfer_mode = HTTP_BODY;

	//if the server response handling thread has not been started yet,
	//start it
	if(NULL == proxy->s.t){
		proxy->s.t = g_thread_create(serve_server, proxy, TRUE, NULL);
		if(NULL==proxy->s.t){
			fprintf(stderr,"ERROR: Can not create new thread\n");
			return -1;
		}
	}

	return 0;
}


static gsize cal_length(long content_length, gsize bufsize){
	if(content_length < 0){
		return bufsize;
	}
	if((unsigned long)content_length > bufsize){
		return bufsize;
	}
	return content_length;
}

//content-length=-1 means read to end
int serve_client_body(p_proxy_sock proxy){
	GIOChannel *cch=proxy->c.gch;
	GIOChannel *sch=proxy->s.gch;
	GIOStatus readr;
	GIOStatus writer;
	gchar buffer[BUFSIZE]={0};
	gsize read_count=0;
	/*long contentl = proxy->c.content_len;*/

	fprintf(stderr, "DEBUG: client body mode\n");

	while(1){
		readr = gch_readchars_trybest(cch, buffer, cal_length(proxy->c.content_len, sizeof(buffer)),
							 &read_count);
		if(readr!=G_IO_STATUS_NORMAL){
			break;
		}
		/*fprintf(stderr, "DEBUG: rec %lu bytes from client\n", read_count);*/

		writer = gch_writechars(sch, buffer, read_count);
		if(writer!=G_IO_STATUS_NORMAL){
			break;
		}
		/*writer = gch_flush(sch);
		if(G_IO_STATUS_NORMAL != writer){
			return -1;
		}*/
		/*fprintf(stderr, "DEBUG: writes %lu bytes server\n", read_count);*/

		if(proxy->c.content_len==-1){
			continue;
		}
		proxy->c.content_len -= read_count;
		if(proxy->c.content_len == 0){
			proxy->c.r_transfer_mode = HTTP_HEADER;
			/*fprintf(stderr, "DEBUG: sent %ld bytes client request body\n", contentl);*/
			return 0;
		}
	}

	if(readr == G_IO_STATUS_EOF){
		writer = gch_flush(sch);
	}

	return -1;
}


void handle_client_connect_error_clean(p_proxy_sock proxy)
{
	if(NULL == proxy){
		return;
	}
	if(proxy->c.gch){
		g_io_channel_shutdown(proxy->c.gch, 1, NULL);
		g_io_channel_unref(proxy->c.gch);
	}
	if(proxy->s.gch){
		g_io_channel_shutdown(proxy->s.gch, 1, NULL);
		g_io_channel_unref(proxy->s.gch);
	}
#ifdef WIN32
	if(proxy->c.sock != INVALID_SOCKET){
		shutdown(proxy->c.sock,SHUT_RDWR);
		closesocket(proxy->c.sock);
	}
	if(proxy->s.sock != INVALID_SOCKET){
		shutdown(proxy->s.sock,SHUT_RDWR);
		closesocket(proxy->s.sock);
	}
#else
	if(proxy->c.sock != INVALID_SOCKET){
		shutdown(proxy->c.sock,SHUT_RDWR);
		close(proxy->c.sock);
	}
	if(proxy->s.sock != INVALID_SOCKET){
		shutdown(proxy->s.sock,SHUT_RDWR);
		close(proxy->s.sock);
	}
#endif
	if(proxy->c.headers){
		g_ptr_array_unref(proxy->c.headers);
	}
	if(proxy->s.headers){
		g_ptr_array_unref(proxy->s.headers);
	}
	g_free(proxy);
	return;
}


gpointer serve_server(gpointer data){
	p_proxy_sock proxy = data;

	if((proxy = (p_proxy_sock)data) == NULL){
		return NULL;
	}

	if(proxy->ishttps){
		GIOStatus r;
		//HTTPS: send ACCEPTED to client
		//Connection Established
		/*const char* httpsok="HTTP/1.1 200 Connection Established\r\n\r\n";*/
		const char* httpsok="HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 0\r\n\r\n";
		proxy->s.r_transfer_mode = HTTP_BODY;
		proxy->s.content_len = -1;
		r = gch_writechars(proxy->c.gch, httpsok, strlen(httpsok));
		if(G_IO_STATUS_NORMAL != r){
			return NULL;
		}
		fprintf(stderr, "DEBUG: sent HTTPS accepted to client\n");
		/*r = gch_flush(proxy->c.gch);
		if(G_IO_STATUS_NORMAL != r){
			return -1;
		}*/
	}

	while(serve_server_funs[proxy->s.r_transfer_mode](proxy)!=-1){
		;
	}

	fprintf(stderr, "INFO: Server closes connection\n");

	shutdown(proxy->s.sock,SHUT_RD);
	g_io_channel_get_flags(proxy->s.gch);
	shutdown(proxy->c.sock,SHUT_WR);
	g_io_channel_get_flags(proxy->c.gch);
	return NULL;
}


int serve_server_header(p_proxy_sock proxy){
	gchar *line=NULL;
	gsize line_len=0;
	gsize term_pos=0;
	GIOChannel *sch=proxy->s.gch;
	GIOStatus r;

	fprintf(stderr, "DEBUG: server header mode\n");

	proxy->s.headers = g_ptr_array_new();
	if(proxy->s.headers == NULL){
		return -1;
	}

	while(1){
		//process through all the headers
		r = gch_readline(sch, &line, &line_len, &term_pos);
		if(r != G_IO_STATUS_NORMAL){
			return -1;
		}

		if(!strncmp(line, "\r\n", line_len)){
			//headers over
			g_free(line);
			line = NULL;
			line_len = 0;
			break;
		}

		http_content_length_detect(line, line_len, &(proxy->s.content_len));

		{
			gboolean persist = FALSE;
			if(http_persistent_connection_detect(line, line_len, &persist)){
				if(HTTP10 == proxy->c.http_ver){
					g_free(line);
					line = NULL;
					line = g_strdup("Connection: close\r\n");
					line_len = strlen("Connection: close\r\n");
				}else{
					if(!persist){
						proxy->persistent_conn = FALSE;
					}
				}
			}
		}

		g_ptr_array_add(proxy->s.headers, (gpointer)line);
	}

	/*{
		gsize len = proxy->s.headers->len;
		gsize i = 0;
		for(i = 0; i < len; ++i){
			fprintf(stderr, "INFO: header %s", (char*)g_ptr_array_index(proxy->s.headers, i));
		}
	}*/

	{
		//send all the headers and \r\n to the client
		gsize len = proxy->s.headers->len;
		/*fprintf(stderr, "DEBUG: server header len: %lu\n", len);*/
		gsize i = 0;
		char *s = NULL;
		for(i = 0; i < len; ++i){
			s = (char*)g_ptr_array_index(proxy->s.headers, i);
			r = gch_writechars(proxy->c.gch, s, strlen(s));
			if(G_IO_STATUS_NORMAL != r){
				return -1;
			}
		}
		r = gch_writechars(proxy->c.gch, "\r\n", 2);
		if(G_IO_STATUS_NORMAL != r){
			return -1;
		}
		/*fprintf(stderr, "DEBUG: send server header over\n");*/
		/*r = gch_flush(proxy->c.gch);
		if(G_IO_STATUS_NORMAL != r){
			return -1;
		}*/
	}

	//free the headers and goto http body handling mode,
	g_ptr_array_free(proxy->s.headers, TRUE);
	g_ptr_array_unref(proxy->s.headers);
	proxy->s.headers = NULL;
	proxy->s.r_transfer_mode = HTTP_BODY;

	return 0;
}


int serve_server_body(p_proxy_sock proxy){
	GIOChannel *cch=proxy->c.gch;
	GIOChannel *sch=proxy->s.gch;
	GIOStatus readr;
	GIOStatus writer;
	gchar buffer[BUFSIZE]={0};
	gsize read_count=0;
	/*long contentl = proxy->s.content_len;*/

	fprintf(stderr, "DEBUG: server body mode\n");

	while(1){
		readr = gch_readchars_trybest(sch, buffer, cal_length(proxy->s.content_len, sizeof(buffer)),
							 &read_count);
		if(readr!=G_IO_STATUS_NORMAL){
			break;
		}
		/*fprintf(stderr, "DEBUG: rec %lu bytes from server\n", read_count);*/

		writer = gch_writechars(cch, buffer, read_count);
		if(writer!=G_IO_STATUS_NORMAL){
			break;
		}
		/*writer = gch_flush(cch);
		if(G_IO_STATUS_NORMAL != writer){
			return -1;
		}*/
		/*fprintf(stderr, "DEBUG: writes %lu bytes client\n", read_count);*/

		if(proxy->s.content_len==-1){
			continue;
		}
		proxy->s.content_len -= read_count;
		if(proxy->s.content_len == 0){
			proxy->s.r_transfer_mode = HTTP_HEADER;
			/*fprintf(stderr, "DEBUG: sent %ld bytes server response body\n", contentl);*/
			return 0;
		}
	}

	if(readr == G_IO_STATUS_EOF){
		writer = gch_flush(sch);
	}

	return -1;
}



PSOCK proxy_connect(const char *domain, int port)
{
	PSOCK white_sock=0;
	struct addrinfo hints, *servinfo, *p;
	char ports[10]={0};
	gint r=0;
	char ipstr[INET6_ADDRSTRLEN]={0};
	struct sockaddr_in * ipv4;
	struct sockaddr_in6 * ipv6;
	void * addr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	sprintf(ports,"%d",port);

	r=getaddrinfo(domain, ports, &hints, &servinfo);

	if(r!=0){
		fprintf(stderr, "ERROR: domain %s port %d getaddrinfo: %s\n", domain, port, gai_strerror(r));
		return INVALID_SOCKET;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {

		if ((white_sock = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == INVALID_SOCKET) {
				perror("server: socket");
				continue;
		}

#ifdef WIN32
		if(p->ai_family==AF_INET){
			ipv4=(struct sockaddr_in *)p->ai_addr;
			fprintf(stderr,"INFO: Connecting to address %s port %d\n",inet_ntoa(ipv4->sin_addr),ipv4->sin_port);
		}else{
			fprintf(stderr,"INFO: Connecting to domain %s port %d\n",domain,port);
		}
#else
		addr=NULL;
		if(p->ai_family==AF_INET){
			ipv4=(struct sockaddr_in *)p->ai_addr;
			addr=&(ipv4->sin_addr);
		}else if(p->ai_family==AF_INET6){
			ipv6=(struct sockaddr_in6 *)p->ai_addr;
			addr=&(ipv6->sin6_addr);
		}else{
			fprintf(stderr,"INFO: Connecting to an address that is neither ipv4 nor ipv6\n");
		}
		if(addr!=NULL){
			inet_ntop(p->ai_family,addr,ipstr,sizeof(ipstr));
			fprintf(stderr,"INFO: Connecting to [%s]:%s\n",ipstr,ports);
		}
#endif

		r=connect(white_sock,(struct sockaddr*)p->ai_addr,p->ai_addrlen);
		if(r<0){
#ifdef WIN32
			closesocket(white_sock);
#else
			close(white_sock);
#endif
			perror("server: connect");;
			continue;
		}

		break;
	}

	if (p == NULL)  {
		fprintf(stderr, "ERROR: server: failed to connect\n");
		return INVALID_SOCKET;
	}

	freeaddrinfo(servinfo); // all done with this structure

	return white_sock;
}



gint transform_http_request_uri(const gchar* srcbuf, gint srclen, gchar* desbuf){
	//change GET http://example.com/a/b.c HTTP/1.1 into
	//GET /a/b.c HTTP/1.1
	//change GET http://example.com HTTP/1.1 into
	//GET / HTTP/1.1
	const char *schema_sep = NULL;
	const char *schema_start = NULL;
	const char *host_end = NULL;
	schema_sep = g_strstr_len(srcbuf, srclen, "://");
	if(NULL == schema_sep){
		return -1;
	}
	schema_start = schema_sep;
	while((schema_start - 1 > srcbuf) && !isspace(*(schema_start - 1))){
		--schema_start;
	}
	if(schema_start - 1 == srcbuf){
		return -1;
	}

	host_end = schema_sep + 3;  //3 = strlen("://")
	while((host_end < srcbuf + srclen) &&
		  (*host_end != '/') && (*host_end != ' ')){
		++host_end;
	}
	memcpy(desbuf, srcbuf, schema_start - srcbuf);
	desbuf += schema_start - srcbuf;
	if(*host_end == ' '){
		*desbuf = '/';
		++desbuf;
	}
	memcpy(desbuf, host_end, srclen - (host_end - srcbuf));
	desbuf[srclen - (host_end - schema_start)] = '\0';

	return 1;
}


GIOStatus gch_readline(GIOChannel *gch, gchar **line, gsize *line_len, gsize *term_pos){
	GIOStatus r;
	r = g_io_channel_read_line(gch, line, line_len, term_pos, NULL);
	while(G_IO_STATUS_AGAIN == r){
		r = g_io_channel_read_line(gch, line, line_len, term_pos, NULL);
	}
	/*if(G_IO_STATUS_NORMAL == r){
		fprintf(stderr, "INFO: header %s", *line);
	}*/
	return r;
}


GIOStatus gch_readchars_full(GIOChannel *gch, gchar *buf, gsize count, gsize *bytes_read){
	GIOStatus r;
	r = g_io_channel_read_chars(gch, buf, count, bytes_read, NULL);
	while(G_IO_STATUS_AGAIN == r){
		r = g_io_channel_read_chars(gch, buf, count, bytes_read, NULL);
	}
	return r;
}


GIOStatus gch_readchars_trybest(GIOChannel *gch, gchar *buf, gsize count, gsize *bytes_read){
	GIOStatus r;
	GIOCondition b;
	gsize readc = 0;
	gsize read1b = 0;
#ifdef WIN32
	long recc = 0;
#else
	ssize_t recc = 0;
#endif
	b = g_io_channel_get_buffer_condition(gch);
	while((b & G_IO_IN) && (readc < count)){
		r = g_io_channel_read_chars(gch, buf + readc, 1, &read1b, NULL);
		if(G_IO_STATUS_NORMAL != r){
			if(readc > 0){
				*bytes_read = readc;
				return G_IO_STATUS_NORMAL;
			}
			*bytes_read = 0;
			return r;
		}
		readc += read1b;
		b = g_io_channel_get_buffer_condition(gch);
	}

	recc = recv(g_io_channel_unix_get_fd(gch), buf + readc, count - readc, 0);
	while(recc < 0){
		if(recc < 0 && errno != EINTR){
			break;
		}
		recc = recv(g_io_channel_unix_get_fd(gch), buf + readc, count - readc, 0);
	}
	if(recc == 0){
		*bytes_read = readc;
		return G_IO_STATUS_NORMAL;
	}
	if(recc < 0){
		*bytes_read = 0;
		return G_IO_STATUS_ERROR;
	}

	*bytes_read = readc + recc;
	return G_IO_STATUS_NORMAL;
}


GIOStatus gch_flush(GIOChannel *gch){
	GIOStatus r;
	r = g_io_channel_flush(gch, NULL);
	while(r == G_IO_STATUS_AGAIN){
		r = g_io_channel_flush(gch, NULL);
	}
	return r;
}


GIOStatus gch_writechars(GIOChannel *gch, const gchar *buf, gssize count){
	GIOStatus r;
	const gchar *p=buf;
	gssize to_write_count=count;
	gsize written_count=0;

	r = g_io_channel_write_chars(gch, p, to_write_count, &written_count, NULL);
	p += written_count;
	to_write_count -= written_count;
	while(G_IO_STATUS_AGAIN == r && to_write_count > 0){
		r = g_io_channel_write_chars(gch, p, to_write_count, &written_count, NULL);
		p += written_count;
		to_write_count -= written_count;
	}
	//If the return value of g_io_write_chars is G_IO_STATUS_NORMAL and the channel is
	//blocking, written_count will always be equal to to_write_count if to_write_count >= 0.
	//That means if we reach here and is G_IO_STATUS_NORMAL, we have written count of bytes.
	return gch_flush(gch);
}
