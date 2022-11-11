CC		:= gcc
CFLAGS	:= -Wall -Werror -Wextra

BIN		:= bin/
SRC		:= src/
OBJ		:= obj/

SOURCES	:= $(wildcard $(SRC)*.c)
OBJETS	:= $(patsubst $(SRC)%.c, $(OBJ)%.o, $(SOURCES))

all: dir main
	$(info )
	$(info -------------------------------------------------------------)
	$(info |                *** Lancer le programme ***                |)
	$(info |                                                           |)
	$(info |              [sudo] bin/main <commutateurs>               |)
	$(info -------------------------------------------------------------)
	$(info )

main: $(OBJETS)
	$(CC) $(CFLAGS) $^ -o $(BIN)main -lpcap

$(OBJ)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) -c $< -o $@

dir:
	mkdir -p $(BIN)
	mkdir -p $(OBJ)

clean:
	rm -rf $(BIN)
	rm -rf $(OBJ)