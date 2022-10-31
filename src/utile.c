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

void verifTaille(const int retourTaille, const size_t tailleBuffer){
	if (retourTaille < 0 || ((size_t) retourTaille) > tailleBuffer){
		fflush(stdout);
		fprintf(stderr, "\n%s|Error| snprintf%s\n", ROUGE, RESET);
		exit(EXIT_FAILURE);
	}
}