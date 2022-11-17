# Configuration de la compilation
CC		:= gcc
CFLAGS	:= -Wall -Werror -Wextra

# Dossiers pour l'organisation
BIN	:= bin/
SRC	:= src/
OBJ	:= obj/

# Liste des fichiers à compiler
SOURCES	:= $(wildcard $(SRC)*.c)
OBJETS	:= $(patsubst $(SRC)%.c, $(OBJ)%.o, $(SOURCES))

# Couleurs pour les messages d'informations
# Reset, Rouge, Vert, Jaune, Bleu
RST	:= $(shell tput sgr0)
R	:= $(RST) $(shell tput setaf 1)
V	:= $(shell tput setaf 2)
J	:= $(shell tput setaf 3)
B	:= $(shell tput bold $&& tput setaf 4)

# Créé les repertoires et lance la compilation
all: dir main
	$(info $(R))
	$(info -------------------------------------------------------------)
	$(info |                $(B)*** Lancer le programme ***$(R)               |)
	$(info |                                                           |)
	$(info |              $(J)[sudo] bin/main <commutateurs>$(R)              |)
	$(info -------------------------------------------------------------)
	$(info |             $(B)*** Commutateurs disponibles ***$(R)             |)
	$(info |                                                           |)
	$(info |      $(V)-i [interface]  -o [fichier pcap]  -f [filtre]$(R)      |)
	$(info |            $(V)-v [verbosité]  -p [nbr de paquets]$(R)           |)
	$(info -------------------------------------------------------------)
	$(info $(RST))

# Compile le binaire
main: $(OBJETS)
	$(CC) $(CFLAGS) $^ -o $(BIN)main -lpcap

# Compile les objets
$(OBJ)%.o: $(SRC)%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Créé les répertoires s'ils n'existent pas déjà
dir:
	mkdir -p $(BIN)
	mkdir -p $(OBJ)

# Supprime les répertoires des objets et du binaire
clean:
	rm -rf $(BIN)
	rm -rf $(OBJ)