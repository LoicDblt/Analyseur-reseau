#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Couleurs pour l'affichage
#define ROUGE	"\033[31m"
#define VERT	"\033[32m"
#define ORANGE	"\033[33m"
#define BLEU	"\033[34m"
#define MAGENTA "\033[35m"
#define CYAN	"\033[36m"
#define JAUNE	"\033[00m"
#define FIN		"\033[00m"

void titreViolet(char* message);
void titreCian(char* message, int compteur);