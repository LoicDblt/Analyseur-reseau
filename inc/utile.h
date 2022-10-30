#ifndef UTILE_H 
#define UTILE_H

/************** INCLUDES **************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/************* CONSTANTES *************/

// Couleurs pour l'affichage
#define ROUGE	"\033[31m"
#define VERT	"\033[32m"
#define JAUNE	"\033[33m"
#define BLEU	"\033[34m"
#define MAGENTA "\033[35m"
#define CYAN	"\033[36m"
#define RESET	"\033[00m"

/************* FONCTIONS **************/

// Titre de premier niveau
void titreCian(const char* message, const int compteur);

// Titre de second niveau
void titreViolet(const char* message);

#endif