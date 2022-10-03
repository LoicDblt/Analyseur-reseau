#include "utile.h"

void titreViolet(char* message){
	printf("%s*** %s ***%s\n", MAGENTA, message, FIN);
}
void titreCian(char* message, int compteur){
	if (compteur == -1)
		printf("\t%s#### %s ####%s\n", CYAN, message, FIN);
	else
		printf("\t%s#### %d%s ####%s\n", CYAN, compteur, message, FIN);
}