#include "../inc/dns.h"

void verifTaille(const int retourTaille, const size_t element){
	if (retourTaille < 0 || ((size_t) retourTaille) >= element){
		fflush(stdout);
		fprintf(stderr, "\n%s|Error| snprintf%s\n", ROUGE, RESET);
		exit(EXIT_FAILURE);
	}
}

void affichageDuree(const unsigned int dureeSecondes){
	unsigned int h, m, s;

	h = dureeSecondes / 3600;
	m = (dureeSecondes - (3600 * h)) / 60;
	s = dureeSecondes - (3600 * h) - (m * 60);

	if (h > 0)
		printf("(%d hours, %d minutes, %d seconds)", h, m, s);
	else if (m > 0)
		printf("(%d minutes, %d seconds)", m, s);
	else
		printf("(%d seconds)", s);
}

void affichageType(const unsigned int type){
	printf("\n\tType : ");
		switch(type){
			/* A */
			case A:
				printf("A (Host adress)");
				break;

			/* NS */
			case NS:
				printf("NS (Authoritative name server)");
				break;

			/* CNAME */
			case CNAME:
				printf("CNAME (Canonical NAME for an alias)");
				break;

			/* SOA */
			case SOA:
				printf("SOA (Start of a zone of authority)");
				break;

			/* WKS */
			case WKS:
				printf("WKS (Well known service description)");
				break;

			/* PTR */
			case PTR:
				printf("PTR (Domain name pointer)");
				break;

			/* HINFO */
			case HINFO:
				printf("HINFO (Host information)");
				break;

			/* MINFO */
			case MINFO:
				printf("MINFO (Mailbox or mail list information)");
				break;

			/* MX */
			case MX:
				printf("MX (Mail exchange)");
				break;

			/* TXT */
			case TXT:
				printf("TXT (Text strings)");
				break;

			/* Inconnu */
			default:
				printf("Unsupported");
				break;
		}
		printf(" (%d)", type);
}

void affichageClasse(const unsigned int classe){
	printf("\n\tClass : ");
		switch(classe){
			/* IN */
			case IN:
				printf("IN");
				break;

			/* CS */
			case CS:
				printf("CS");
				break;

			/* CH */
			case CH:
				printf("CH");
				break;

			/* HS */
			case HS:
				printf("HS");
				break;

			/* Inconnu */
			default:
				printf("Unknown");
				break;
		}
		printf(" (0x%04x)", classe);
}

void gestionDNS(const u_char* paquet, const int size_udp){
	// On se place après l'entête UDP
	u_int8_t* pointeurDns =  (u_int8_t*) paquet + size_udp;
	unsigned int hexUn, hexDeux, hexTrois, hexQuatre, concatHex;
	unsigned int nbrQuestions, nbrReponses;

	char nomDomaine[TAILLEMAX];

	titreViolet("DNS");
	printf(JAUNE);

	printf("Transaction ID : 0x");
	for (int i = 0; i < 2; i++){
		printf("%02x", *pointeurDns);
		pointeurDns++;
	}

	printf("\nFlags : 0x");
	for (int i = 0; i < 2; i++){
		printf("%02x", *pointeurDns);
		pointeurDns++;
	}

	hexUn = *pointeurDns++; 				// Récupère le premier hexa
	hexDeux = *pointeurDns++;				// Récupère le second hexa
	concatHex = (hexUn << 8) | (hexDeux);	// Concatène les deux
	printf("\nQuestions : %d", concatHex);
	nbrQuestions = (int) concatHex;

	hexUn = *pointeurDns++;
	hexDeux = *pointeurDns++;
	concatHex = (hexUn << 8) | (hexDeux);
	printf("\nAnswer RRs : %d", concatHex);
	nbrReponses = concatHex;

	hexUn = *pointeurDns++;
	hexDeux = *pointeurDns++;
	concatHex = (hexUn << 8) | (hexDeux);
	printf("\nAuthority RRs : %d", concatHex);

	hexUn = *pointeurDns++;
	hexDeux = *pointeurDns++;
	concatHex = (hexUn << 8) | (hexDeux);
	printf("\nAdditional RRs : %d", concatHex);

	// S'il y a des "queries"
	if (nbrQuestions > 0){
		printf("\nQueries :");

		while (nbrQuestions > 0){
			nbrQuestions--;
			printf("\n\tName : ");
			u_int8_t hexa = *pointeurDns++;
			int tailleNom = 0, nbrLabels = 1, i = 0, retourTaille = 0;
			while(1){
				hexa = *pointeurDns++;

				if (hexa == FIN)
					break;
				if (hexa == POINT1 || hexa == POINT2){
					printf(".");
					nbrLabels++;

					retourTaille = snprintf(nomDomaine, sizeof(nomDomaine),
						"%s.", nomDomaine);
					verifTaille(retourTaille, sizeof(nomDomaine));
				}
				else{
					printf("%c", hexa);
					retourTaille = snprintf(nomDomaine, sizeof(nomDomaine),
						"%s%c", nomDomaine, hexa);
					verifTaille(retourTaille, sizeof(nomDomaine));
				}
				tailleNom++;
			}
			printf("\n\t[Name length] : %d", tailleNom);
			printf("\n\t[Label count] : %d", nbrLabels);

			// Type
			hexUn = *pointeurDns++;
			hexDeux = *pointeurDns++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageType(concatHex);

			// Classe
			hexUn = *pointeurDns++;
			hexDeux = *pointeurDns++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageClasse(concatHex);

			printf("\n");
		}
	}

	// S'il y a des "answers"
	if (nbrReponses > 0){
		printf("\nAnswers :");

		while (nbrReponses > 0){
			nbrReponses--;

			unsigned int type;
			hexUn = *pointeurDns++;
			hexDeux = *pointeurDns++;
			concatHex = (hexUn << 8) | (hexDeux);
			printf("\n\tName : ");
			if (concatHex == AFFICHEA || concatHex == AFFICHECNAME)
				printf("%s", nomDomaine);
			else
				printf("Unknown (0x%04x)", concatHex);

			// Type
			hexUn = *pointeurDns++;
			hexDeux = *pointeurDns++;
			concatHex = (hexUn << 8) | (hexDeux);
			type = concatHex;
			affichageType(type);

			// Classe
			hexUn = *pointeurDns++;
			hexDeux = *pointeurDns++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageClasse(concatHex);

			// Time to live
			hexUn = *pointeurDns++;
			hexDeux = *pointeurDns++;
			hexTrois = *pointeurDns++;
			hexQuatre = *pointeurDns++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tTime to live : %d ", concatHex);
			affichageDuree(concatHex);

			// Data length
			hexUn = *pointeurDns++;
			hexDeux = *pointeurDns++;
			concatHex = (hexUn << 8) | (hexDeux);
			printf("\n\tData length : %d", concatHex);

			// Adress
			printf("\n\tAddress : ");
			if (type == CNAME){
				// Vide le nom de domaine précédement enregistré
				memset(nomDomaine, 0, sizeof(nomDomaine));

				unsigned int hexa = *pointeurDns++;

				int retourTaille = 0;
				for (int i = 0; i < concatHex; i++){
					hexa = *pointeurDns++;

					if (hexa == FIN)
						break;
					if (hexa == POINT1 || hexa == POINT2){
						printf(".");
						retourTaille = snprintf(nomDomaine, sizeof(nomDomaine),
							"%s.", nomDomaine);
						verifTaille(retourTaille, sizeof(nomDomaine));
					}
					else{
						printf("%c", hexa);
						retourTaille = snprintf(nomDomaine, sizeof(nomDomaine),
							"%s%c", nomDomaine, hexa);
						verifTaille(retourTaille, sizeof(nomDomaine));
					}
				}
			}
			else{
				affichageIP(pointeurDns, concatHex);
				pointeurDns += concatHex;
			}

			printf("\n");
		}
	}
}