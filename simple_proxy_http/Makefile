CTAG = ctags
ALL_C_FILE:=$(wildcard *.c)
CC = gcc
CFLAGS = -O3 -Wall -g `pkg-config --cflags glib-2.0`  `pkg-config --cflags gthread-2.0`
LDFLAGS = `pkg-config --libs glib-2.0` `pkg-config --libs gthread-2.0`
OBJS = simple_proxy_http.o

all: simple_proxy_http _tags

simple_proxy_http: $(OBJS) 

clean: _tagsclean
	rm -f $(OBJS) simple_proxy_http dependencies tags

_tagsclean:
	rm -f tags

dependencies: $(OBJS:.o=.c)
	$(CC) -MM $^ $(CFLAGS) > $@
	
_tags: tags

tags: $(ALL_C_FILE)
	$(CTAG) --fields=+S --langmap=c:+.h --languages=c,c++ --links=yes --c-kinds=+p --recurse=yes .

include dependencies
