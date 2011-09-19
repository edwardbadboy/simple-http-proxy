#include "simple_proxy_http.h"
#include "add.h"

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

int main(int argc, char* argv[])
{
	if(init_proxy(argc,argv)==-1){
		fprintf(stderr,"error: Failed to initialize thread support or network!\n");
		return -1;
	}

	return do_monitor();
}

gint init_proxy(int argc, char* argv[])
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
		fprintf(stderr, "error: getaddrinfo: %s\n", gai_strerror(rv));
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
			//ipv4=(struct sockaddr_in *)p->ai_addr;
			//ipv4->sin_port=htons(0);
			ret=WSAAddressToStringA(p->ai_addr,p->ai_addrlen,NULL,ipstr,&sl);
			fprintf(stderr,"info: Server binded at address %s\n",ipstr);
			//fprintf(stderr,"info: Server binded at address %s:%d\n",inet_ntoa(ipv4->sin_addr),G_my_port);
		}else{
			int sl=sizeof(ipstr),ret=0;
			//ipv6=(struct sockaddr_in6 *)p->ai_addr;
			//ipv6->sin6_port=htons((unsigned short)0);
			ret=WSAAddressToStringA(p->ai_addr,p->ai_addrlen,NULL,ipstr,&sl);
			fprintf(stderr,"info: Server binded at address %s\n",ipstr);
			//fprintf(stderr,"info Server binded\n");
		}
#else
		if(p->ai_family==AF_INET){
			ipv4=(struct sockaddr_in *)p->ai_addr;
			addr=&(ipv4->sin_addr);
		}else if(p->ai_family==AF_INET6){
			ipv6=(struct sockaddr_in6 *)p->ai_addr;
			addr=&(ipv6->sin6_addr);
		}else{
			fprintf(stderr,"info: Server binded at an address that is neither ipv4 nor ipv6\n");
			break;
		}

		inet_ntop(p->ai_family,addr,ipstr,sizeof(ipstr));

		fprintf(stderr,"info: Server binded at address %s:%s\n",ipstr,argv[1]);
#endif
		break;
	}

	if (p == NULL)  {
		fprintf(stderr, "error: Server failed to bind\n");
		return 2;
	}

	freeaddrinfo(servinfo);


//	
//	if((G_my_sock =socket(AF_INET, SOCK_STREAM, 0)) == -1){
//		/* 输出错误提示并退出 */
//		perror("socket");
//		return -1;
//	}
//
//	if(INVALID_SOCKET==G_my_sock){
//		fprintf(stderr,"error: Can not create a socket\n");
//#ifdef WIN32
//		closesocket(G_my_sock);
//#else
//		close(G_my_sock);
//#endif
//		return -1;
//	}
//
//	/* 主机字节顺序 */
//	G_my_addr.sin_family = AF_INET;
//	/* 网络字节顺序,短整型 */
//	G_my_addr.sin_port = htons(G_my_port);
//	/* 将运行程序机器的IP 填充入s_addr */
//	G_my_addr.sin_addr.s_addr = INADDR_ANY;
//	/* 将此结构的其余空间清零 */
//	memset(&(G_my_addr.sin_zero),0, 8);
//
//	setsockopt(G_my_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&gsockflag, sizeof(gsockflag));
//
//	/* 错误检查 */ 
//	if (bind(G_my_sock, (struct sockaddr *)&G_my_addr,sizeof(struct sockaddr)) == -1){
//		/* 如果调用bind()失败,则给出错误提示,退出 */
//		perror("bind");
//		return -1;
//	}

#ifndef WIN32
	sigemptyset(&G_sa.sa_mask);
	G_sa.sa_flags=0;
	G_sa.sa_handler = SIG_IGN; 
	if(sigaction( SIGPIPE, &G_sa, 0 )<0){
		fprintf(stderr,"error: Failed to install SIGPIPE signal handler\n");
		return -1;
	}
#endif

	//fprintf(stderr,"proxy server: binded at %s:%d\n", inet_ntoa(G_my_addr.sin_addr),G_my_port);

	return 0;
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
		proxy=NULL;
		proxy=(p_proxy_sock)g_try_malloc0(sizeof(proxy_sock));
		if(proxy==NULL){
			g_usleep(1000000l);
			continue;
		}
		G_sin_size = sizeof(struct sockaddr_storage);
		if ((proxy->c_sock = accept(G_my_sock, (struct sockaddr *)&(proxy->client_addr), &G_sin_size)) == -1){
			/* 如果调用accept()出现错误,则给出错误提 */
			perror("accept");
			g_free(proxy);
		}
#ifdef WIN32
		if(proxy->client_addr.ss_family==AF_INET){
			int sl=sizeof(ipstr),ret=0;
			//ipv4=(struct sockaddr_in *)&(proxy->client_addr);
			ret=WSAAddressToStringA((struct sockaddr*)&(proxy->client_addr),sizeof(proxy->client_addr),NULL,ipstr,&sl);
			fprintf(stderr,"info: Accepted client connection from %s\n",ipstr);
			//fprintf(stderr,"info: Accepted client connection from %s:%d\n",inet_ntoa(ipv4->sin_addr),ipv4->sin_port);
		}else{
			int sl=sizeof(ipstr),ret=0;
			ret=WSAAddressToStringA((struct sockaddr*)&(proxy->client_addr),sizeof(proxy->client_addr),NULL,ipstr,&sl);
			fprintf(stderr,"info: Accepted client connection from %s\n",ipstr);
			//fprintf(stderr,"info: Accepted client connection\n");
		}
#else
		addr=NULL;
		if(proxy->client_addr.ss_family==AF_INET){
			ipv4=(struct sockaddr_in *)&(proxy->client_addr);
			addr=&(ipv4->sin_addr);
			sprintf(ports,"%d",ipv4->sin_port);
		}else if(proxy->client_addr.ss_family==AF_INET6){
			ipv6=(struct sockaddr_in6 *)&(proxy->client_addr);
			addr=&(ipv6->sin6_addr);
			sprintf(ports,"%d",ipv6->sin6_port);
		}else{
			fprintf(stderr,"info: Accepted client that is neither ipv4 nor ipv6\n");
		}
		if(addr!=NULL){
			inet_ntop(proxy->client_addr.ss_family,addr,ipstr,sizeof(ipstr));
			fprintf(stderr,"info: Accepted client connection from [%s]:%s\n",ipstr,ports);
		}
#endif
		proxy->client_t=g_thread_create(handle_client_connect,proxy,FALSE,NULL);
		if(NULL==proxy->client_t){
			fprintf(stderr,"error: Can not create thread for handling new connections!\n");
#ifdef WIN32
			closesocket(proxy->c_sock);
#else
			close(proxy->c_sock);
#endif
			g_free(proxy);
			g_usleep(10000l);
		}
	}
	return 0;
}

gpointer handle_client_connect(gpointer data)
{
	p_proxy_sock proxy=NULL;
	gchar buffer[BUFSIZE]={0};
	gint numbytes=0;
	gint total=0;
	gchar host[1024]={0};
	gint port=80;
	gboolean ishttps=FALSE;

	if( (proxy=(p_proxy_sock)data)==NULL ){
		return NULL;
	}
	while(total<=sizeof(buffer)-1){
		numbytes=recv(proxy->c_sock,buffer+total,sizeof(buffer)-total-1,0);
		if(-1==numbytes || 0==numbytes){
			handle_client_connect_error_clean(proxy);
			fprintf(stderr,"error: Can not get init data from client\n");
			return NULL;
		}
		total+=numbytes;
		buffer[total]=0;
		//fprintf(stderr,"info: Received client init data:\n%s\n",buffer);
		port=get_host_and_port(buffer,host,sizeof(host),&ishttps);
		//fprintf(stderr,"info: ishttps?:\n%d\n",ishttps);
		if(-1!=port){
			break;
		}
		if(NULL!=g_strstr_len(buffer,-1,"\r\n\r\n")){
			break;
		}
	}
	proxy->ishttps=ishttps;
	//fprintf(stderr,"info: connect ishttps?:\n%d\n",proxy->ishttps);
	if(-1==port){
		handle_client_connect_error_clean(proxy);
		fprintf(stderr,"error: Can not get server ip and port\n");
		return NULL;
	}
	proxy->s_sock=proxy_connect(host,port);
	if(-1==proxy->s_sock){
		handle_client_connect_error_clean(proxy);
		fprintf(stderr,"error: Can not connect to server\n");
		return NULL;
	}
	proxy->server_t=g_thread_create(handle_client_receive_data,proxy,TRUE,NULL);
	if(NULL==proxy->server_t){
		handle_client_connect_error_clean(proxy);
		fprintf(stderr,"error: Can not create new thread\n");
		return NULL;
	}

	handle_client_send_data(proxy,buffer,numbytes);

	g_usleep(1000000);
	g_thread_join(proxy->server_t);
	handle_client_connect_error_clean(proxy);

	return NULL;
}

void handle_client_connect_error_clean(p_proxy_sock proxy)
{
	if(NULL==proxy){
		return;
	}
#ifdef WIN32
	closesocket(proxy->c_sock);
	closesocket(proxy->s_sock);
#else
	close(proxy->c_sock);
	close(proxy->s_sock);
#endif
	g_free(proxy);
	//fprintf(stderr,"info: Proxy data cleaned\n");
	return;
}

int handle_client_send_data(p_proxy_sock proxy,gchar* origin_buff,gint buf_len)
{
	char buf[BUFSIZE]={0};
	char tmpbuf[BUFSIZE+100]={0};
	gint count=0;
	gint modify_count=0;
	gint r=0;

	//fprintf(stderr,"info: snd ishttps?:\n%d\n",proxy->ishttps);

	if(FALSE==(proxy->ishttps)){
		fprintf(stderr,"info: http connection\n");
		modify_count=modify_http_first_line(origin_buff,buf_len,tmpbuf);
		if(0==modify_count){
			//memset(tmpbuf,0,sizeof(tmpbuf));
			//memcpy(tmpbuf,origin_buff,buf_len);
			//fprintf(stderr,"info: not modified req:\n%s\n",tmpbuf);
			if(send(proxy->s_sock,origin_buff, buf_len, 0) == -1){
				fprintf(stderr,"error: Can not send to server\n");
				return -2;
			}
		}else{
			//fprintf(stderr,"info: modified init req:\n%s\n",tmpbuf);
			if(send(proxy->s_sock,tmpbuf, modify_count, 0) == -1){
				fprintf(stderr,"error: Can not send to server\n");
				return -2;
			}
		}
	}else{
		fprintf(stderr,"info: https connection\n");
	}

	while(1){
		count=recv(proxy->c_sock,buf,sizeof(buf)-1,0);
		if(count<0){
			fprintf(stderr,"error: Can not receive from client\n");
			r=-1;
			break;
		}else if(0==count){
			fprintf(stderr,"info: Client connection closed\n");
			r=0;
			break;
		}
		
		//fprintf(stderr,"info: Received client req data:\n%s\n",buf);
		//memset(tmpbuf,0,sizeof(tmpbuf));
		if(FALSE==(proxy->ishttps)){
			modify_count=modify_http_first_line(buf,count,tmpbuf);
		}else{
			modify_count=0;
		}

		if(0==modify_count){
			//memcpy(tmpbuf,buf,count);
			//fprintf(stderr,"info: not modified req:\n%s\n",tmpbuf);
			if(send(proxy->s_sock,buf, count, 0) == -1){
				fprintf(stderr,"error: Can not send to server\n");
				r=-2;
				break;
			}
		}else{
			//fprintf(stderr,"info: modified req:\n%s\n",tmpbuf);
			if(send(proxy->s_sock,tmpbuf, modify_count, 0) == -1){
				fprintf(stderr,"error: Can not send to server\n");
				r=-2;
				break;
			}
		}
	}
	shutdown(proxy->s_sock,SHUT_WR);
	shutdown(proxy->c_sock,SHUT_RD);
	return r;
}

gpointer handle_client_receive_data(gpointer data)
{
	p_proxy_sock proxy=NULL;
	char* httpsok="HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 0\r\n\r\n";
	char buf[BUFSIZE]={0};
	gint count=0;
	gint r=0;

	if(data==NULL){
		return NULL;
	}
	proxy=(p_proxy_sock)data;

	//fprintf(stderr,"info: rec ishttps?:\n%d\n",proxy->ishttps);

	if(TRUE==(proxy->ishttps)){
		strncpy(buf,httpsok,sizeof(buf));
		count=strlen(httpsok);
		if(send(proxy->c_sock,buf, count, 0) == -1){
			fprintf(stderr,"error: Can not send to client\n");
			return NULL;
		}
	}

	while(1){
		count=recv(proxy->s_sock,buf,sizeof(buf),0);
		if(count<0){
			fprintf(stderr,"error: Can not receive from server\n");
			r=-1;
			break;
		}else if(0==count){
			fprintf(stderr,"info: Server connection closed\n");
			r=0;
			break;
		}
		if(send(proxy->c_sock,buf, count, 0) == -1){
			fprintf(stderr,"error: Can not send to client\n");
			r=-2;
			break;
		}
	}
	shutdown(proxy->s_sock,SHUT_RD);
	shutdown(proxy->c_sock,SHUT_WR);
	return NULL;
}

PSOCK proxy_connect (char *domain,int port)
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
	//hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	sprintf(ports,"%d",port);

	r=getaddrinfo(domain, ports, &hints, &servinfo);

	if(r!=0){
		fprintf(stderr, "error: getaddrinfo: %s\n", gai_strerror(r));
		return -1;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {

		if ((white_sock = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == INVALID_SOCKET) {
				perror("server: socket");
				continue;
		}

#ifdef WIN32
		if(p->ai_family==AF_INET){
			ipv4=(struct sockaddr_in *)p->ai_addr;
			fprintf(stderr,"info: Connecting to address %s port %d\n",inet_ntoa(ipv4->sin_addr),ipv4->sin_port);
		}else{
			fprintf(stderr,"info: Connecting to domain %s port %d\n",domain,port);
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
			fprintf(stderr,"info: Connecting to an address that is neither ipv4 nor ipv6\n");
		}
		if(addr!=NULL){
			inet_ntop(p->ai_family,addr,ipstr,sizeof(ipstr));
			fprintf(stderr,"info: Connecting to [%s]:%s\n",ipstr,ports);
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
		fprintf(stderr, "error: server: failed to connect\n");
		return -2;
	}

	freeaddrinfo(servinfo); // all done with this structure


	/*r=get_host_addr(domain,&site);
	if(r<0){
		fprintf(stderr,"error: Failed to do a DNS lookup\n");
		return -2;
	}
	white_sock = socket (AF_INET, SOCK_STREAM, 0 ) ;
	if(white_sock<=0){
		fprintf(stderr,"error: Can not create new sock\n");
		return -1;
	}
	memset(&host_addr,0,sizeof(struct sockaddr_in));
	memcpy(&host_addr.sin_addr,site.h_addr_list[0],site.h_length);
	host_addr.sin_family = AF_INET;
	host_addr.sin_port = htons(port);*/

	return white_sock;
}

////////////todo: 代码有问题gethostbyname_r返回的东西是放在buf里的，而这个buf在函数返回后是无效的
//int get_host_addr(char *domain,struct hostent * hp)
//{
//
//
//#ifdef WIN32
//	struct hostent *site=NULL;
//	site = gethostbyname(domain);
//	if(site==NULL){
//		return -1;
//	}else{
//		memcpy(hp,site,sizeof(struct hostent));
//	}
//#else
//	struct hostent site;
//	int res=0;
//	int herrno=0;
//	char buf[1024]={0};
//	struct hostent *result = NULL;
//
//	res = gethostbyname_r(domain, &site, buf, sizeof(buf), &result, &herrno);
//	if (res || !result || !site.h_addr_list || !site.h_addr_list[0]){
//		return -1;
//	}else{
//		memcpy(hp,&site,sizeof(struct hostent));
//	}
//#endif
//	return 0;
//}

int get_host_and_port(gchar* buffer,gchar* host,gint host_len,gboolean* is_https)
{
	gint port=80;
	gchar* host_s=NULL;
	gchar* host_e=NULL;
	gchar* port_pos=NULL;
	gchar* connect_pos=NULL;
	gchar* rn_pos=NULL;

	if(is_https!=NULL){
		*is_https=FALSE;
	}

	host_s=g_strstr_len(buffer,-1,"Host: ");
	if(host_s==NULL){
		fprintf(stderr,"error: Can not get Host from req\n");
		return -1;
	}
	host_s+=6;
	host_e=g_strstr_len(host_s,-1,"\r\n");
	if(NULL==host_e){
		fprintf(stderr,"error: Can not get \\r\\n from req\n");
		return -1;
	}
	if(host_e-host_s > host_len-1){
		fprintf(stderr,"error: Host string is too long: len=%d, allow len=%d\n",host_e-host_s,host_len-1);
		return -1;
	}
	port_pos=g_strrstr_len(host_s,host_e-host_s,":");
	if(port_pos==NULL){
		sscanf(host_s,"%s",host);
	}else{
		sscanf(port_pos+1,"%d",&port);
		sscanf(host_s,"%s",host);
		port_pos=g_strstr_len(host,-1,":");
		if(port_pos!=NULL){
			*port_pos=0;
		}
	}
	//fprintf(stderr,"info: http host %s port %d\n",host,port);
	//return port;

	//https support
	connect_pos=g_strstr_len(buffer,-1,"CONNECT ");
	if(connect_pos==NULL){
		//fprintf(stderr,"info: http host %s port %d\n",host,port);
		return port;
	}
	connect_pos+=8;
	rn_pos=g_strstr_len(connect_pos,-1,"HTTP/1.0\r\n");
	if(NULL==rn_pos){
		rn_pos=g_strstr_len(connect_pos,-1,"HTTP/1.1\r\n");
	}
	if(NULL==rn_pos){
		return port;
	}
	port_pos=g_strrstr_len(connect_pos,rn_pos-connect_pos,":");
	if(port_pos==NULL){
		return port;
	}
	sscanf(port_pos+1,"%d",&port);
	//fprintf(stderr,"info: https host %s port %d\n",host,port);
	if(is_https!=NULL){
		(*is_https)=TRUE;
	}
	return port;
}

gint modify_http_first_line(gchar* srcbuf,gint srclen,gchar* desbuf)
{
	char* http_pos=NULL;
	char* rn_pos=NULL;
	char* slash_pos=NULL;
	gint true_count=0;
	gint http_len=0;
	gint http_slash_len=0;
	char* src_i_pos=NULL;
	gint dst_i=0;
	char* getpost_pos=NULL;

	getpost_pos=g_strstr_len(srcbuf,srclen,"GET ");
	if(NULL==getpost_pos){
		getpost_pos=g_strstr_len(srcbuf,srclen,"POST ");
	}
	if(NULL==getpost_pos){
		//memcpy(desbuf,srcbuf,srclen);
		return 0;
	}

	rn_pos=g_strstr_len(getpost_pos,srclen-(getpost_pos-srcbuf),"HTTP/1.0\r\n");
	if(rn_pos==NULL){
		rn_pos=g_strstr_len(getpost_pos,srclen-(getpost_pos-srcbuf),"HTTP/1.1\r\n");
	}

	if(rn_pos==NULL){
		//fprintf(stderr,"error: no \\r\\n\n");
		//memcpy(desbuf,srcbuf,srclen);
		return 0;
	}

	http_pos=g_strstr_len(getpost_pos,rn_pos-getpost_pos,"://");
	http_len=4;//strlen("http");
	http_slash_len=7;//strlen("http://");
	if(http_pos==NULL){
		//fprintf(stderr,"error: no http://\n");
		//memcpy(desbuf,srcbuf,srclen);
		return 0;
	}else{
		http_pos-=http_len;
	}
	slash_pos=g_strstr_len(http_pos+http_slash_len,rn_pos-http_pos-http_slash_len,"/");
	if(slash_pos==NULL){
		//fprintf(stderr,"error: no /\n");
		slash_pos=g_strstr_len(http_pos+http_slash_len,rn_pos-http_pos-http_slash_len," ");
	}
	if(slash_pos==NULL){
		//fprintf(stderr,"error: no ' '\n");
		//memcpy(desbuf,srcbuf,srclen);
		return 0;
	}
	dst_i=0;
	if(getpost_pos!=srcbuf){
		memcpy(desbuf,srcbuf,getpost_pos-srcbuf);
		dst_i+=getpost_pos-srcbuf;
	}
	src_i_pos=getpost_pos;
	while(src_i_pos<http_pos){
		desbuf[dst_i]=*src_i_pos;
		++dst_i;
		++src_i_pos;
	}
	if(*slash_pos==' '){
		desbuf[dst_i]='/';
		dst_i++;
	}
	memcpy(desbuf+dst_i,slash_pos,(srcbuf+srclen)-slash_pos);
	true_count=dst_i+((srcbuf+srclen)-slash_pos);
	return true_count;
}
