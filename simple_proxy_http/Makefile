ALL_C_FILE:=$(wildcard *.c)
CC = gcc
CFLAGS = -O0 -Wall -Wextra -g3 -ggdb `pkg-config --cflags glib-2.0`  `pkg-config --cflags gthread-2.0`
LDFLAGS = `pkg-config --libs glib-2.0` `pkg-config --libs gthread-2.0`
OBJS = simple_proxy_http.o

all: simple_proxy_http

simple_proxy_http: $(OBJS) 

clean:
	rm -f $(OBJS) simple_proxy_http dependencies

dependencies: $(OBJS:.o=.c)
	$(CC) -MM $^ $(CFLAGS) > $@
	
include dependencies
