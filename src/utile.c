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

void affichageAdresseMAC(const u_int8_t* pointeur){
	// Entre l'adresse dans la structure
	struct ether_addr adresse;
	for (unsigned int i = 0; i < ETHER_ADDR_LEN; i++){
		#if __APPLE__
			adresse.octet[i] = *pointeur++;
		#else
			adresse.ether_addr_octet[i] = *pointeur++;
		#endif
	}
	printf("%s", ether_ntoa(&adresse));
}

void affichageAdresseIPv4(const u_int8_t* pointeur, const u_int8_t longueur){
	// Copie l'adresse dans une structure IPv4
	struct in_addr adresse;
	memcpy((void*)&adresse, pointeur, longueur);

	// Converti en string l'adresse du réseau
	char buff[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &adresse, buff, INET_ADDRSTRLEN);

	printf("%s", buff);
}

void affichageAdresseIPv6(const u_int8_t* pointeur, const u_int8_t longueur){
	// Copie l'adresse dans une structure IPv6
	struct in6_addr adresse;
	memcpy((void*)&adresse, pointeur, longueur);

	// Converti en string l'adresse du réseau
	char buff[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &adresse, buff, INET6_ADDRSTRLEN);

	printf("%s", buff);
}

unsigned int affichageNomDomaine(const u_int8_t* pointeur,
	const unsigned int longueur
){
	unsigned int hexa = *pointeur++, nbrIncrPtr = 0;
	int retourTaille = 0;
	char nomDomaine[255] = "";

	// Boucle sur la taille de données récupérée précédemment
	for (nbrIncrPtr = 0; nbrIncrPtr < longueur; nbrIncrPtr++){
		hexa = *pointeur++;
		int offset;

		if (hexa == FIN)
			break;

		// Code ASCII spécial
		if (hexa == CODE_ASCII){
			nbrIncrPtr += 2;
			break;
		}
		else if (hexa < CODE_CONTROLE && nbrIncrPtr > 0){
			offset = strlen(nomDomaine);
			retourTaille = snprintf(nomDomaine + offset,
				sizeof(nomDomaine) - offset, ".");
			verifTaille(retourTaille, sizeof(nomDomaine));
		}
		else{
			offset = strlen(nomDomaine);
			retourTaille = snprintf(nomDomaine + offset,
				sizeof(nomDomaine) - offset, "%c", hexa);
			verifTaille(retourTaille, sizeof(nomDomaine));
		}
	}
	printf("%s", nomDomaine);
	return nbrIncrPtr;
}