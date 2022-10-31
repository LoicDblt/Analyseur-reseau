#include "../inc/utile.h"

void titreCian(const char* message, const int compteur){
	if (compteur == -1)
		printf("\t%s#### %s ####%s\n", CYAN, message, RESET);
	else
		printf("\t%s#### %s %d ####%s\n", CYAN, message, compteur, RESET);
}

void titreViolet(const char* message){
	printf("\n\n%s*** %s ***%s\n", MAGENTA, message, JAUNE);
}

void verifTaille(const int retourTaille, const size_t tailleBuffer){
	if (retourTaille < 0 || ((size_t) retourTaille) > tailleBuffer){
		fflush(stdout);
		fprintf(stderr, "\n%s|Error| snprintf%s\n", ROUGE, RESET);
		exit(EXIT_FAILURE);
	}
}

void affichageAdresseMAC(const u_char* adresse){
	unsigned int addr;
	int typeAddr = 0;

	for (unsigned int i = 0; i < MAC_ADDR_SIZE; i++){
		addr = (unsigned int) adresse[i];

		// Permet de détecter les "ff"
		if (addr == 255)
			typeAddr++;

		printf("%.2x", addr);
		if (i < 5)
			printf(":");
	}

	if (typeAddr == MAC_ADDR_SIZE)
		printf(" (Broadcast)");
}

void affichageAdresseIP(const u_int8_t* pointeur, const u_int8_t longueur){
	int nbrPoints = 0;
	for (unsigned int i = 0; i < longueur; i++){
		printf("%d", pointeur[i]);

		if (nbrPoints/3){
			nbrPoints = 0;
			if (i+1 < longueur)
				printf(" and ");
		}
		else{
			printf(".");
			nbrPoints++;
		}
	}
}