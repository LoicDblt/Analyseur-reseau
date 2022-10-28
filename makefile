CC=gcc
CFLAGS = -Wall -Werror -Wextra -lpcap

bin = bin/
obj = obj/
src = src/

all: message main utile ethernet ip udp tcp bootp
	$(CC) $(obj)main.o $(obj)utile.o $(obj)ethernet.o $(obj)ip.o $(obj)udp.o \
		$(obj)tcp.o $(obj)bootp.o -o $(bin)main $(CFLAGS)

message:
	$(info )
	$(info *** Pour lancer le programme : sudo bin/main <commutateurs> ***)
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

tcp:
	$(CC) -c $(src)tcp.c -o $(obj)tcp.o

bootp:
	$(CC) -c $(src)bootp.c -o $(obj)bootp.o

clean:
	rm $(obj)*.o
	rm $(bin)main