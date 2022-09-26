CC=gcc
CFLAGS=-Wall -Wextra
EXEC=main

all: main

main: analyseur.c
	$(CC) -c analyseur.c
	$(CC) analyseur.o -o analyseur -lpcap

clean:
	rm analyseur