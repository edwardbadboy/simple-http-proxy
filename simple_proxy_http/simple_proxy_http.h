#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

#define BUFSIZE 1

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


typedef enum _http_mode {
	HTTP_HEADER=0,
	HTTP_BODY,
}http_mode;


typedef enum _http_version {
	HTTP10=0,
	HTTP11,
}http_version;


typedef struct _endpoint_status {
	PSOCK sock;
	GIOChannel *gch;
	struct sockaddr_storage addr;
	GThread* t;
	http_mode r_transfer_mode;
	long content_len;
	http_version http_ver;
	GPtrArray *headers;
}endpoint_status;


typedef struct _proxy_sock{
	endpoint_status c;
	endpoint_status s;
	gboolean ishttps;
	gboolean persistent_conn;
}proxy_sock,*p_proxy_sock;


gint setup_sockets(int argc, char* argv[]);
gint do_monitor();

gpointer serve_client(gpointer data);
int serve_client_header(p_proxy_sock proxy);
int serve_client_body(p_proxy_sock proxy);

void handle_client_connect_error_clean(p_proxy_sock proxy);

gpointer serve_server(gpointer data);
int serve_server_header(p_proxy_sock proxy);
int serve_server_body(p_proxy_sock proxy);

void endpoint_status_init(endpoint_status *st);
p_proxy_sock proxy_new();

PSOCK proxy_connect(const char *domain,int port);
gint transform_http_request_uri(const gchar* srcbuf, gint srclen, gchar* desbuf);

GIOStatus gch_readline(GIOChannel *gch, gchar **line, gsize *line_len, gsize *term_pos);
GIOStatus gch_readchars(GIOChannel *gch, gchar *buf, gsize count, gsize *bytes_read);
GIOStatus gch_flush(GIOChannel *gch);
GIOStatus gch_writechars(GIOChannel *gch, const gchar *buf, gssize count);
