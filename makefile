CC		:= gcc
CFLAGS	:= -Wall -Werror -Wextra

BIN		:= bin/
SRC		:= src/
OBJ		:= obj/

SOURCES	:= $(wildcard $(SRC)*.c)
OBJETS	:= $(patsubst $(SRC)%.c, $(OBJ)%.o, $(SOURCES))

all: main
	$(info )
	$(info *** Pour lancer le programme : [sudo] bin/main <commutateurs> ***)
	$(info )

main: $(OBJETS)
	$(CC) $(CFLAGS) -lpcap $^ -o $(BIN)main

$(OBJ)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm $(OBJ)*.o
	rm $(BIN)main