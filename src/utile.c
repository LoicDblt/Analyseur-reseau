#include "../inc/utile.h"

void titreCian(const char* message, const int compteur){
	if (compteur == -1)
		printf("\t%s#### %s ####%s\n", CYAN, message, RESET);
	else
		printf("\t%s#### %s %d ####%s\n", CYAN, message, compteur, RESET);
}

void titreViolet(const char* message){
	printf("\n\n%s*** %s ***%s\n", MAGENTA, message, RESET);
}