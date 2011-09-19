CTAG = ctags
ALL_C_FILE:=$(wildcard *.c)
ALL_C_FUNC:=$(patsubst %.c,%.func,$(wildcard *.c))
CC = gcc
CFLAGS = -O3 -Wall -g -I/usr/include/glib-2.0/ -I/usr/lib/glib-2.0/include/
LDFLAGS = -L/usr/local/lib/ -lglib-2.0 -lgthread-2.0
OBJS = simple_proxy_http.o

all: simple_proxy_http _tags

simple_proxy_http: $(OBJS) 

clean: _tagsclean
	rm -f $(OBJS) simple_proxy_http dependencies tags *.func

_tagsclean:
	rm -f tags *.func */*.func

dependencies: $(OBJS:.o=.c)
	$(CC) -MM $^ $(CFLAGS) > $@
	
_tags: $(ALL_C_FUNC) tags

tags: $(ALL_C_FILE)
	$(CTAG) --fields=+S --langmap=c:+.h --languages=c,c++ --links=yes --c-kinds=+p --recurse=yes .

%.func: %.c
	$(CTAG) --c-kinds=f -f $@ $<

include dependencies
