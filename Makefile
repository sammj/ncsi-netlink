#FLAGS=$(shell /usr/bin/pkg-config --libs --cflags libnl-3.0 libnl-genl-3.0)

# Cross compiling against a local copy of libnl
FLAGS=-I$(LIBNL_INCDIR)
LIBS=-L$(LIBNL_LIBDIR) -l:libnl-genl-3.so.200 -l:libnl-3.so.200

all:
	$(CC) ncsi-netlink.c -o ncsi-netlink -Wall $(FLAGS) $(LIBS)

clean:
	rm ncsi-netlink
