CC = gcc
CFLAGS = -Wall -O2
LIBS = -lssl -lcrypto

all: libdews.a

libdews.a: dews.o
	ar rcs $@ $^

dews.o: dews.c dews.h
	$(CC) $(CFLAGS) -c dews.c -o dews.o

clean:
	rm -f *.o *.a *.so

install: libdews.a
	mkdir -p ../lib
	cp libdews.a ../lib/
	cp dews.h ../include/
