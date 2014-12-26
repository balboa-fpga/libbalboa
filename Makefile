LIB_SRCS := libbalboa.c
LIB_OBJS := $(LIB_SRCS:.c=.o)

INSTALLDIR := /opt/balboa

CFLAGS := -O2 -Wall -I.

all: libbalboa.a

libbalboa.a: $(LIB_OBJS)
	rm -f libbalboa.a
	$(AR) r libbalboa.a $(LIB_OBJS)

install: libbalboa.a
	mkdir -p $(INSTALLDIR)/lib
	mkdir -p $(INSTALLDIR)/include
	cp -f libbalboa.a $(INSTALLDIR)/lib
	cp -f balboa.h $(INSTALLDIR)/include

clean:
	rm -f libbalboa.a *.o
