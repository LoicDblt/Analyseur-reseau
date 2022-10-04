#include "utile.h"

void titreCian(char* message, int compteur){
	if (compteur == -1)
		printf("\t%s#### %s ####%s\n", CYAN, message, FIN);
	else
		printf("\t%s#### %d%s ####%s\n", CYAN, compteur, message, FIN);
}

void titreViolet(char* message){
	if (strstr(message, "IP")) // Corrige l'affichage pour les infos d'IP
		printf("\n\n");
	printf("%s*** %s ***%s\n", MAGENTA, message, FIN);
}