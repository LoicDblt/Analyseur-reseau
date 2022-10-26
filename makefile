CC=gcc
CFLAGS = -Wall -Werror -Wextra -lpcap

bin = bin/
inc = inc/
obj = obj/
src = src/

all: message main utile ethernet ip udp bootp
	$(CC) $(obj)main.o $(obj)utile.o $(obj)ethernet.o $(obj)ip.o $(obj)udp.o \
		$(obj)bootp.o -o $(bin)main $(CFLAGS)

message:
	$(info )
	$(info *** Pour lancer le programme : sudo bin/main <flags> ***)
	$(info )

main:
	$(CC) -c $(src)main.c -o $(obj)main.o

utile:
	$(CC) -c $(src)utile.c -o $(obj)utile.o

ethernet:
	$(CC) -c $(src)ethernet.c -o $(obj)ethernet.o

ip:
	$(CC) -c $(src)ip.c -o $(obj)ip.o

udp:
	$(CC) -c $(src)udp.c -o $(obj)udp.o

bootp:
	$(CC) -c $(src)bootp.c -o $(obj)bootp.o

clean:
	rm $(obj)*.o
	rm $(bin)main