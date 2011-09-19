#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
	#define WIN32_LEAN_AND_MEAN		// 从 Windows 头中排除极少使用的资料
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <signal.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <unistd.h>
#endif
#include <errno.h>
#include <glib.h>

#define BUFSIZE 4096

#ifdef WIN32
#define PSOCK SOCKET
#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH
#define SOCKLEN_T gint
#else
#define PSOCK gint
#define INVALID_SOCKET  (PSOCK)(~0)
#define SOCKLEN_T socklen_t
#endif

typedef struct _proxy_sock
{
	PSOCK c_sock;
	PSOCK s_sock;
	//struct sockaddr client_addr;
	//struct sockaddr server_addr;
	struct sockaddr_storage client_addr;
	struct sockaddr_storage server_addr;
	GThread* client_t;
	GThread* server_t;
	gboolean ishttps;
}proxy_sock,*p_proxy_sock;

gint init_proxy(int argc, char* argv[]);
gint do_monitor();
gpointer handle_client_connect(gpointer data);
void handle_client_connect_error_clean(p_proxy_sock proxy);
int handle_client_send_data(p_proxy_sock proxy,gchar* origin_buff,gint buf_len);
gpointer handle_client_receive_data(gpointer data);

int get_host_and_port(gchar* buffer,gchar* host,gint host_len,gboolean* is_https);
PSOCK proxy_connect (char *domain,int port);
//int get_host_addr(char *domain,struct hostent * hp);
gint modify_http_first_line(gchar* srcbuf,gint srclen,gchar* desbuf);


//todo: release mem when 2 threads finished
