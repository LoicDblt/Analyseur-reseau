CC=gcc

all: main.o utile.o ethernet.o ip.o udp.o bootp.o
	$(CC) main.o utile.o ethernet.o ip.o udp.o bootp.o -o main -Wall -Wextra -Werror -lpcap

main: main.c ethernet.h utile.h
	$(CC) -c main.c -o main.o

utile: utile.c utile.h
	$(CC) -c utile.c -o utile.o

ethernet: ethernet.c ethernet.h utile.h
	$(CC) -c ethernet.c -o ethernet.o

ip: ip.c ip.h utile.h
	$(CC) -c ip.c -o ip.o

udp: udp.c udp.h utile.h
	$(CC) -c udp.c -o udp.o

bootp: bootp.c bootp.h utile.h
	$(CC) -c bootp.c -o bootp.o

clean:
	rm *.o main