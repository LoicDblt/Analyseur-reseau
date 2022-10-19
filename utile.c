#include "utile.h"

void titreCian(char* message, int compteur){
	if (compteur == -1)
		printf("\t%s#### %s ####%s\n", CYAN, message, RESET);
	else
		printf("\t%s#### %d%s ####%s\n", CYAN, compteur, message, RESET);
}

void titreViolet(char* message){
	if (strstr(message, "IP")) // Corrige l'affichage pour les infos d'IP
		printf("\n\n");
	printf("%s*** %s ***%s\n", MAGENTA, message, RESET);
}