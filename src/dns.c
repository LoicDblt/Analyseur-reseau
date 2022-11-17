#include "../inc/dns.h"

void affichageDureeConvertie(unsigned int dureeSecondes){
	unsigned int j, h, m, s;

	// Jours
	j = dureeSecondes / SEC_DANS_JOUR;
	dureeSecondes -= j * SEC_DANS_JOUR;

	// Heures
	h = dureeSecondes / SEC_DANS_HEURE;
	dureeSecondes -= h * SEC_DANS_HEURE;

	// Minutes
	m = dureeSecondes / SEC_DANS_MIN;
	dureeSecondes -= m * SEC_DANS_MIN;

	// Secondes
	s = dureeSecondes;

	if (j > 0 || h > 0 || m > 0 || s > 0){
		printf("(");

		// Jours
		if (j > 0){
			printf("%d day", j);

			// Ajoute un "s" si il y a plusieurs jours
			if (j > 1)
				printf("s");

			if (h > 0 || m > 0 || s > 0)
				printf(", ");
		}

		// Heures
		if (h > 0){
			printf("%d hour", h);
			if (h > 1)
				printf("s");
			if (m > 0 || s > 0)
				printf(", ");
		}

		// Minutes
		if (m > 0){
			printf("%d minute", m);
			if (m > 1)
				printf("s");
			if (s > 0)
				printf(", ");
		}

		// Secondes
		if (s > 0){
			printf("%d second", s);
			if (s > 1)
				printf("s");
		}

		printf(")");
	}
	else
		printf("(%d seconds)", s);
}

void affichageType(const unsigned int type){
	printf("\n\tType : ");
		switch (type){
			/* A */
			case A:
				printf("A (Host address)");
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
				printf("PTR (Domain name PoinTeR)");
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

			/* AAAA */
			case AAAA:
				printf("AAAA (IPv6 address)");
				break;

			/* Inconnu */
			default:
				printf("Unsupported");
				break;
		}
		printf(" (0x%04x)", type);
}

void affichageAdresse(const unsigned int type, const u_int8_t* pointeurDNS,
	const unsigned int taille
){
	printf("\n\tAddress : ");
	switch(type){
		/* A */
		case A:
			affichageAdresseIPv4(pointeurDNS, taille);
			break;

		/* CNAME */
		case CNAME:
			affichageNomDomaine(pointeurDNS, taille);
			break;

		/* PTR */
		case PTR:
			affichageNomDomaine(pointeurDNS, taille);
			break;

		/* AAAA */
		case AAAA:
			affichageAdresseIPv6(pointeurDNS, taille);
			break;

		/* Non pris en charge */
		default:
			printf("Unsupported (%d)", type);
			break;
	}
}

void affichageClasse(const unsigned int classe){
	printf("\n\tClass : ");
		switch (classe){
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

unsigned int recupereNiemeBit(const unsigned int nombre,
	const unsigned int nieme
){
	return (nombre >> ((TAILLE_BIT-1)-nieme)) & 1;
}

void affichageBinaire(const unsigned int nombre,
	const unsigned int nieme, const unsigned int nbrContigu
){
	printf("\n");
	for (unsigned int i = 0; i < TAILLE_BIT; i++){
		if (i == nieme){
			printf("%d", recupereNiemeBit(nombre, nieme));
			for (unsigned int j = 1; j < nbrContigu; j++){
				printf("%d", recupereNiemeBit(nombre, nieme+j));
				i++;
			}
		}
		else
			printf(".");
	}
}

void gestionDNS(const u_char* paquet, const int offset){
	// On place un pointeur après l'entête UDP
	u_int8_t* pointeurDNS = (u_int8_t*) paquet + offset;

	unsigned int hexUn, hexDeux, hexTrois, hexQuatre, concatHex;
	unsigned int bitUn, bitDeux, bitTrois, bitQuatre, concatBit, retourBit;
	unsigned int nbrQuestions, nbrReponses, nbrAutorite, nbrSupplementaire;
	unsigned int nbrIncrPtr;

	char nomDomaine[TAILLE_NOM_DOM] = "";

	titreProto("DNS", ROUGE);

	hexUn = *pointeurDNS++; 				// Récupère le premier hexa
	hexDeux = *pointeurDNS++;				// Récupère le second hexa
	concatHex = (hexUn << 8) | (hexDeux);	// Concatène les deux
	if (niveauVerbo > SYNTHETIQUE)
		printf("Transaction ID : 0x%04x", concatHex);

	// Flags
	hexUn = *pointeurDNS++;
	hexDeux = *pointeurDNS++;
	concatHex = (hexUn << 8) | (hexDeux);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\nFlags : 0x%04x", concatHex);
	int niemeBit = 0;

		// Response
	if (niveauVerbo > SYNTHETIQUE)
		affichageBinaire(concatHex, niemeBit, 1);

	unsigned int typeReponse = recupereNiemeBit(concatHex, niemeBit);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\t");

	if (niveauVerbo > CONCIS){
	printf("Response : ");
		if (typeReponse == REPONSE)
			printf("Message is a response");
		else
			printf("Message is a query");
	}

		// Op code
	bitUn = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo > SYNTHETIQUE)
		affichageBinaire(concatHex, niemeBit, 4);
	bitDeux = recupereNiemeBit(concatHex, ++niemeBit);
	bitTrois = recupereNiemeBit(concatHex, ++niemeBit);
	bitQuatre = recupereNiemeBit(concatHex, ++niemeBit);
	concatBit = (bitUn << 3) | (bitDeux << 2) | (bitTrois << 1) | (bitQuatre);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\tOp code : ");

	switch (concatBit){
		/* Query */
		case QUERY:
			if (niveauVerbo > SYNTHETIQUE)
				printf("Standard query");
			break;

		/* Iquery */
		case IQUERY:
			if (niveauVerbo > SYNTHETIQUE)
				printf("Inverse query");
			break;

		/* Status */
		case STATUS:
			if (niveauVerbo > SYNTHETIQUE)
				printf("Server status request");
			break;

		/* Inconnu */
		default:
			if (niveauVerbo > SYNTHETIQUE)
				printf("Unknown");
			break;
	}
	if (niveauVerbo > SYNTHETIQUE)
		printf(" (%d)", concatBit);

	// Authoritative
	if (typeReponse == REPONSE){
		retourBit = recupereNiemeBit(concatHex, ++niemeBit);

		if (niveauVerbo > SYNTHETIQUE){
			affichageBinaire(concatHex, niemeBit, 1);
			printf("\tAuthoritative : ");
			if (retourBit > 0)
				printf("Server is an authority for domain");
			else
				printf("Server is not an authority for domain");
		}
	}
	else
		++niemeBit;

		// Truncated
	retourBit = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo > SYNTHETIQUE){
		affichageBinaire(concatHex, niemeBit, 1);
		printf("\tTruncated : ");
		if (retourBit > 0)
			printf("Message is truncated");
		else
			printf("Message is not truncated");
	}

		// Recursion desired
	retourBit = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo > SYNTHETIQUE){
		affichageBinaire(concatHex, niemeBit, 1);
		printf("\tRecursion desired : ");
		if (retourBit > 0)
			printf("Do query recursively");
		else
			printf("Don't query recursively");
	}

		// Recursion available
	retourBit = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo > SYNTHETIQUE){
		affichageBinaire(concatHex, niemeBit, 1);
		printf("\tRecursion available : ");
		if (retourBit > 0)
			printf("Server can do recursive queries");
		else
			printf("Server can't do recursive queries");
	}

		// Z (Reserved)
	bitUn = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo > SYNTHETIQUE)
		affichageBinaire(concatHex, niemeBit, 3);
	bitDeux = recupereNiemeBit(concatHex, ++niemeBit);
	bitTrois = recupereNiemeBit(concatHex, ++niemeBit);
	concatBit = (bitUn << 3) | (bitDeux << 2) | (bitTrois << 1) | (bitQuatre);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\tZ : ");

	if (concatBit == ALLNULL && niveauVerbo > SYNTHETIQUE)
		printf("Reserved (%d)", concatBit);

		// Reply code
	if (typeReponse == REPONSE){
		bitUn = recupereNiemeBit(concatHex, ++niemeBit);
		if (niveauVerbo > SYNTHETIQUE)
			affichageBinaire(concatHex, niemeBit, 4);
		bitDeux = recupereNiemeBit(concatHex, ++niemeBit);
		bitTrois = recupereNiemeBit(concatHex, ++niemeBit);
		bitQuatre = recupereNiemeBit(concatHex, ++niemeBit);
		concatBit = (bitUn << 3) | (bitDeux << 2) | (bitTrois << 1) |
			(bitQuatre);
		if (niveauVerbo > SYNTHETIQUE){
			printf("\tReply code : ");

			switch (concatBit){
				/* No error */
				case NOERR:
					printf("No error");
					break;

				/* Format error */
				case FORMERR:
					printf("Format error");
					break;

				/* Server failure */
				case FAILERR:
					printf("Server failure ");
					break;

				/* No such name */
				case NAMEERR:
					printf("No such name");
					break;

				/* Not implemented */
				case NOTIMPL:
					printf("Not implemented");
					break;

				/* Refused */
				case REFUSED:
					printf("Refused");
					break;

				/* Inconnu */
				default:
					printf("Unknown");
					break;
			}
			printf(" (%d)", concatBit);
		}
	}

	// Questions
	hexUn = *pointeurDNS++;
	hexDeux = *pointeurDNS++;
	concatHex = (hexUn << 8) | (hexDeux);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\nQuestions : %d", concatHex);
	nbrQuestions = (int) concatHex;

	// Answer RRs
	hexUn = *pointeurDNS++;
	hexDeux = *pointeurDNS++;
	concatHex = (hexUn << 8) | (hexDeux);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\nAnswer RRs : %d", concatHex);
	nbrReponses = concatHex;

	// Authority RRs
	hexUn = *pointeurDNS++;
	hexDeux = *pointeurDNS++;
	concatHex = (hexUn << 8) | (hexDeux);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\nAuthority RRs : %d", concatHex);
	nbrAutorite = concatHex;

	// Additional RRs
	hexUn = *pointeurDNS++;
	hexDeux = *pointeurDNS++;
	concatHex = (hexUn << 8) | (hexDeux);
	if (niveauVerbo > SYNTHETIQUE)
		printf("\nAdditional RRs : %d", concatHex);
	nbrSupplementaire = concatHex;

	// S'il y a des "queries"
	if (nbrQuestions > 0 && niveauVerbo > SYNTHETIQUE){
		printf("\nQueries :");

		while (nbrQuestions > 0){
			nbrQuestions--;

			unsigned int hexa = *pointeurDNS++;
			int tailleNom = 0, nbrLabels = 1, retourTaille = 0;
			while (tailleNom < TAILLE_NOM_DOM){
				hexa = *pointeurDNS++;
				int offset;

				if (hexa == FIN)
					break;
				else if (hexa < CODE_CONTROLE){
					offset = strlen(nomDomaine);
					retourTaille = snprintf(nomDomaine + offset,
						sizeof(nomDomaine) - offset, ".");
					verifTaille(retourTaille, sizeof(nomDomaine));

					nbrLabels++;
				}
				else{
					offset = strlen(nomDomaine);
					retourTaille = snprintf(nomDomaine + offset,
						sizeof(nomDomaine) - offset, "%c", hexa);
					verifTaille(retourTaille, sizeof(nomDomaine));
				}
				tailleNom++;
			}
			printf("\n\tName : %s", nomDomaine);
			printf("\n\t[Name length] : %d", tailleNom);
			printf("\n\t[Label count] : %d", nbrLabels);

			// Type
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageType(concatHex);

			// Classe
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageClasse(concatHex);
		}
	}

	// S'il y a des "answers"
	if (nbrReponses > 0 && niveauVerbo > SYNTHETIQUE){
		printf("\n\nAnswers :");

		while (nbrReponses > 0){
			nbrReponses--;

			// Name
			printf("\n\tName : %s", nomDomaine);
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			if (hexUn < CODE_CONTROLE)
				pointeurDNS += strlen(nomDomaine);

			// Type
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			unsigned int type = concatHex;
			affichageType(type);

			// Classe
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageClasse(concatHex);

			// Time to live
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tTime to live : %d ", concatHex);
			affichageDureeConvertie(concatHex);

			// Data length
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			printf("\n\tData length : %d", concatHex);

			// Address
			affichageAdresse(type, pointeurDNS, concatHex);
			pointeurDNS += concatHex;

			printf("\n");
		}
	}

	// S'il y a des "authority"
	if (nbrAutorite > 0 && niveauVerbo > SYNTHETIQUE){
		printf("\n\nAuthoritative nameservers :");

		while (nbrAutorite > 0){
			nbrAutorite--;

			// Name
			printf("\n\tName : %s", nomDomaine);
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			if (hexUn < CODE_CONTROLE)
				pointeurDNS += strlen(nomDomaine);

			// Type
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			unsigned int type = concatHex;
			affichageType(type);

			// Classe
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageClasse(concatHex);

			// Time to live
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tTime to live : %d ", concatHex);
			affichageDureeConvertie(concatHex);

			// Data length
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			printf("\n\tData length : %d", concatHex);

			// Primary name server
			printf("\n\tPrimary name server : ");
			nbrIncrPtr = affichageNomDomaine(pointeurDNS, concatHex);
			pointeurDNS += nbrIncrPtr;

			// Responsible authority's mailbox
			printf("\n\tResponsible authority's mailbox : ");
			nbrIncrPtr = affichageNomDomaine(++pointeurDNS, concatHex);
			pointeurDNS += nbrIncrPtr + 1;	// Besoin d'incrémenter le pointeur
											// à la valeur suivante

			// Serial number
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tSerial number : %u", concatHex);

			// Refresh interval
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tRefresh interval : %d ", concatHex);
			affichageDureeConvertie(concatHex);

			// Retry interval
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tRetry interval : %d ", concatHex);
			affichageDureeConvertie(concatHex);

			// Expire limit
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tExpire limit : %d ", concatHex);
			affichageDureeConvertie(concatHex);

			// Minimum TTL
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tMinimum TTL : %d ", concatHex);
			affichageDureeConvertie(concatHex);
		}
	}

	// S'il y a des "Additional"
	if (nbrSupplementaire > 0 && niveauVerbo > SYNTHETIQUE){
		printf("\nAdditional records :");

		// Réinitialise le buffer
		memset(nomDomaine, 0, sizeof(nomDomaine));

		while (nbrSupplementaire > 0){
			nbrSupplementaire--;

			unsigned int hexa = *pointeurDNS++;

			int tailleNom = 0, retourTaille = 0;
			while (tailleNom < TAILLE_NOM_DOM){
				// On incrémente pour le cractère qui suit dans ce cas
				if (hexa == CODE_ASCII){
					pointeurDNS++;
					break;
				}

				hexa = *pointeurDNS++;
				int offset;

				if (hexa == FIN)
					break;
				else if (hexa < CODE_CONTROLE){
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
				tailleNom++;
			}
			printf("\n\tName : %s", nomDomaine);

			// Type
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			unsigned int type = concatHex;
			affichageType(concatHex);

			// Classe
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			affichageClasse(concatHex);

			// Time to live
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			hexTrois = *pointeurDNS++;
			hexQuatre = *pointeurDNS++;
			concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
				(hexQuatre);
			printf("\n\tTime to live : %d ", concatHex);
			affichageDureeConvertie(concatHex);

			// Data length
			hexUn = *pointeurDNS++;
			hexDeux = *pointeurDNS++;
			concatHex = (hexUn << 8) | (hexDeux);
			printf("\n\tData length : %d", concatHex);

			// Address
			affichageAdresse(type, pointeurDNS, concatHex);
			pointeurDNS += concatHex;

			printf("\n");
		}
	}
}