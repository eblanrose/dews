# dews/Makefile
CC=gcc
CFLAGS=-fPIC -O2 -Wall $(shell pkg-config --cflags openssl)
LIBS=$(shell pkg-config --libs openssl)
AR=ar

all: libdews.a

libdews.a: dews.o
	$(AR) rcs $@ $^

dews.o: dews.c dews.h
	$(CC) $(CFLAGS) -c dews.c -o dews.o

clean:
	rm -f *.o *.a
