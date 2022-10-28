#include "../inc/utile.h"

void titreCian(const char* message, const int compteur){
	if (compteur == -1)
		printf("\t%s#### %s ####%s\n", CYAN, message, RESET);
	else
		printf("\t%s#### %d%s ####%s\n", CYAN, compteur, message, RESET);
}

void titreViolet(const char* message){
	printf("\n\n%s*** Contenu %s ***%s\n", MAGENTA, message, RESET);
}

void affichageAdresseMac(const u_char* adresse){
	int i;
	unsigned addr;

	for (i = 0; i < 6; i++){
		addr = (unsigned) adresse[i];

		printf("%.2x", addr);
		if (i < 5)
			printf(":");
	}
}

void affichageIP(const u_int8_t* pointeur, const u_int8_t longueur){
	int nbrPoints = 0;
	for (int i = 0; i < longueur; i++){
		printf("%d", pointeur[i]);

		if (nbrPoints/3){
			nbrPoints = 0;
			if (i+1 < longueur)
				printf(" et ");
		}
		else{
			printf(".");
			nbrPoints++;
		}
	}
}