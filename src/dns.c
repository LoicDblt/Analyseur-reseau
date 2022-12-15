#include "../inc/dns.h"

unsigned int concactDeuxOctets(u_int8_t* pointeurDNS){
	unsigned int octUn, octDeux;

	octUn = *pointeurDNS++;
	octDeux = *pointeurDNS++;

	return (octUn << 8) | (octDeux);
}

unsigned int concactQautreOctets(u_int8_t* pointeurDNS){
	unsigned int octUn, octDeux, octTrois, octQuatre;

	octUn = *pointeurDNS++;
	octDeux = *pointeurDNS++;
	octTrois = *pointeurDNS++;
	octQuatre = *pointeurDNS++;

	return (octUn << 24) | (octDeux << 16) | (octTrois << 8) | (octQuatre);
}

void affichageType(const unsigned int type){
	printf("\n\tType: ");
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
	printf(" (%d)", type);
}

void affichageAdresse(const unsigned int type, const u_int8_t* pointeurDNS,
	const unsigned int taille
){
	printf("\n\tAddress: ");
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
	printf("\n\tClass: ");
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
			printf("%u", recupereNiemeBit(nombre, nieme));
			for (unsigned int j = 1; j < nbrContigu; j++){
				printf("%u", recupereNiemeBit(nombre, nieme+j));
				i++;
			}
		}
		else
			printf(".");
	}
}

u_int8_t* affichageInfosAnswer(u_int8_t* pointeurDNS){
	unsigned int concatHex;

	// Type
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	unsigned int type = concatHex;
	affichageType(type);

	// Classe
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	affichageClasse(concatHex);

	// Time to live
	concatHex = concactQautreOctets(pointeurDNS);
	pointeurDNS += 4;
	printf("\n\tTime to live: %u (", concatHex);
	affichageDureeConvertie(concatHex);
	printf(")");

	// Data length
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	printf("\n\tData length: %u", concatHex);

	// Address
	affichageAdresse(type, pointeurDNS, concatHex);
	pointeurDNS += concatHex;

	printf("\n");
	return pointeurDNS;
}

void gestionDNS(const u_char* paquet, const int offset){
	// On place un pointeur après l'entête UDP
	u_int8_t* pointeurDNS = (u_int8_t*) paquet + offset;

	unsigned int octUn, concatHex;
	unsigned int bitUn, bitDeux, bitTrois, bitQuatre, concatBit, retourBit;
	unsigned int nbrQuestions, nbrReponses, nbrAutorite, nbrSupplementaire;
	unsigned int nbrIncrPtr;

	char nomDomaine[TAILLE_NOM_DOM] = "";

	titreProto("DNS", ROUGE);

	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	if (niveauVerbo == COMPLET)
		printf("Transaction ID: 0x%04x", concatHex);

	// Flags
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	if (niveauVerbo == COMPLET)
		printf("\nFlags: 0x%04x", concatHex);
	int niemeBit = 0;

		// Response
	if (niveauVerbo == COMPLET)
		affichageBinaire(concatHex, niemeBit, 1);

	unsigned int typeReponse = recupereNiemeBit(concatHex, niemeBit);
	if (niveauVerbo == COMPLET)
		printf("\t");

	if (niveauVerbo > CONCIS){
	printf("Response: ");
		if (typeReponse == REPONSE)
			printf("Message is a response");
		else
			printf("Message is a query");
	}
	else if (niveauVerbo == CONCIS){
		if (typeReponse == REPONSE)
			printf("Response");
		else
			printf("Query");
	}

		// Op code
	bitUn = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo == COMPLET)
		affichageBinaire(concatHex, niemeBit, 4);
	bitDeux = recupereNiemeBit(concatHex, ++niemeBit);
	bitTrois = recupereNiemeBit(concatHex, ++niemeBit);
	bitQuatre = recupereNiemeBit(concatHex, ++niemeBit);
	concatBit = (bitUn << 3) | (bitDeux << 2) | (bitTrois << 1) | (bitQuatre);
	if (niveauVerbo == COMPLET)
		printf("\tOp code: ");

	switch (concatBit){
		/* Query */
		case QUERY:
			if (niveauVerbo == COMPLET)
				printf("Standard query");
			break;

		/* Iquery */
		case IQUERY:
			if (niveauVerbo == COMPLET)
				printf("Inverse query");
			break;

		/* Status */
		case STATUS:
			if (niveauVerbo == COMPLET)
				printf("Server status request");
			break;

		/* Inconnu */
		default:
			if (niveauVerbo == COMPLET)
				printf("Unknown");
			break;
	}
	if (niveauVerbo == COMPLET)
		printf(" (%u)", concatBit);

	// Authoritative
	if (typeReponse == REPONSE){
		retourBit = recupereNiemeBit(concatHex, ++niemeBit);

		if (niveauVerbo == COMPLET){
			affichageBinaire(concatHex, niemeBit, 1);
			printf("\tAuthoritative: ");
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
	if (niveauVerbo == COMPLET){
		affichageBinaire(concatHex, niemeBit, 1);
		printf("\tTruncated: ");
		if (retourBit > 0)
			printf("Message is truncated");
		else
			printf("Message is not truncated");
	}

		// Recursion desired
	retourBit = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo == COMPLET){
		affichageBinaire(concatHex, niemeBit, 1);
		printf("\tRecursion desired: ");
		if (retourBit > 0)
			printf("Do query recursively");
		else
			printf("Don't query recursively");
	}

		// Recursion available
	if (typeReponse == REPONSE){
		retourBit = recupereNiemeBit(concatHex, ++niemeBit);
		if (niveauVerbo == COMPLET){
			affichageBinaire(concatHex, niemeBit, 1);
			printf("\tRecursion available: ");
			if (retourBit > 0)
				printf("Server can do recursive queries");
			else
				printf("Server can't do recursive queries");
		}
	}
	else
		++niemeBit;

		// Z (Reserved)
	retourBit = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo == COMPLET){
		affichageBinaire(concatHex, niemeBit, 1);
		printf("\tZ: ");

		if (retourBit == 0)
			printf("Reserved (%u)", concatBit);
		else
			printf("Should be reserved (%u)", concatBit);
	}

		// Answer authentificated
	if (typeReponse == REPONSE){
		retourBit = recupereNiemeBit(concatHex, ++niemeBit);
		if (niveauVerbo == COMPLET){
			affichageBinaire(concatHex, niemeBit, 1);
			printf("\tAnswer authentificated: ");
			if (retourBit > 0)
				printf("Answer/authority was authenticated by the server");
			else{
				printf("Answer/authority portion was not authenticated by the "
					"server");
			}
		}
	}
	else
		++niemeBit;

		// Authentificated data
	retourBit = recupereNiemeBit(concatHex, ++niemeBit);
	if (niveauVerbo == COMPLET){
		affichageBinaire(concatHex, niemeBit, 1);
		if (retourBit > 0)
			printf("\tAuthentificated data");
		else
			printf("\tNon-authentificated data: Unacceptable");
	}

		// Reply code
	if (typeReponse == REPONSE){
		bitUn = recupereNiemeBit(concatHex, ++niemeBit);
		if (niveauVerbo == COMPLET)
			affichageBinaire(concatHex, niemeBit, 4);
		bitDeux = recupereNiemeBit(concatHex, ++niemeBit);
		bitTrois = recupereNiemeBit(concatHex, ++niemeBit);
		bitQuatre = recupereNiemeBit(concatHex, ++niemeBit);
		concatBit = (bitUn << 3) | (bitDeux << 2) | (bitTrois << 1) |
			(bitQuatre);
		if (niveauVerbo == COMPLET){
			printf("\tReply code: ");

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
			printf(" (%u)", concatBit);
		}
	}

	// Questions
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	if (niveauVerbo == COMPLET)
		printf("\nQuestions: %u", concatHex);
	nbrQuestions = (int) concatHex;

	// Answer RRs
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	if (niveauVerbo == COMPLET)
		printf("\nAnswer RRs: %u", concatHex);
	nbrReponses = concatHex;

	// Authority RRs
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	if (niveauVerbo == COMPLET)
		printf("\nAuthority RRs: %u", concatHex);
	nbrAutorite = concatHex;

	// Additional RRs
	concatHex = concactDeuxOctets(pointeurDNS);
	pointeurDNS += 2;
	if (niveauVerbo == COMPLET)
		printf("\nAdditional RRs: %u", concatHex);
	nbrSupplementaire = concatHex;

	// S'il y a des "queries"
	if (nbrQuestions > 0 && niveauVerbo == COMPLET){
		printf("\nQueries:");

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
			printf("\n\tName: %s", nomDomaine);
			printf("\n\t[Name length: %u]", tailleNom);
			printf("\n\t[Label count: %u]", nbrLabels);

			// Type
			concatHex = concactDeuxOctets(pointeurDNS);
			pointeurDNS += 2;
			affichageType(concatHex);

			// Classe
			concatHex = concactDeuxOctets(pointeurDNS);
			pointeurDNS += 2;
			affichageClasse(concatHex);
		}
	}

	// S'il y a des "answers"
	if (nbrReponses > 0 && niveauVerbo == COMPLET){
		printf("\n\nAnswers:");

		while (nbrReponses > 0){
			nbrReponses--;

			// Name
			printf("\n\tName: %s", nomDomaine);
			octUn = *pointeurDNS;
			pointeurDNS += 2;
			if (octUn < CODE_CONTROLE)
				pointeurDNS += strlen(nomDomaine);

			pointeurDNS = affichageInfosAnswer(pointeurDNS);
		}
	}

	// S'il y a des "authority"
	if (nbrAutorite > 0 && niveauVerbo == COMPLET){
		printf("\n\nAuthoritative nameservers:");

		while (nbrAutorite > 0){
			nbrAutorite--;

			// Name
			printf("\n\tName: %s", nomDomaine);
			octUn = *pointeurDNS;
			pointeurDNS += 2;
			if (octUn < CODE_CONTROLE)
				pointeurDNS += strlen(nomDomaine);

			// Type
			concatHex = concactDeuxOctets(pointeurDNS);
			pointeurDNS += 2;
			unsigned int type = concatHex;
			affichageType(type);

			// Classe
			concatHex = concactDeuxOctets(pointeurDNS);
			pointeurDNS += 2;
			affichageClasse(concatHex);

			// Time to live
			concatHex = concactQautreOctets(pointeurDNS);
			pointeurDNS += 4;
			printf("\n\tTime to live: %u (", concatHex);
			affichageDureeConvertie(concatHex);
			printf(")");

			// Data length
			concatHex = concactDeuxOctets(pointeurDNS);
			pointeurDNS += 2;
			printf("\n\tData length: %u", concatHex);

			// Primary name server
			printf("\n\tPrimary name server: ");
			nbrIncrPtr = affichageNomDomaine(pointeurDNS, concatHex);
			pointeurDNS += nbrIncrPtr;

			// Responsible authority's mailbox
			printf("\n\tResponsible authority's mailbox: ");
			nbrIncrPtr = affichageNomDomaine(++pointeurDNS, concatHex);
			pointeurDNS += nbrIncrPtr + 1;	// Besoin d'incrémenter le pointeur
											// à la valeur suivante

			// Serial number
			concatHex = concactQautreOctets(pointeurDNS);
			pointeurDNS += 4;
			printf("\n\tSerial number: %u", concatHex);

			// Refresh interval
			concatHex = concactQautreOctets(pointeurDNS);
			pointeurDNS += 4;
			printf("\n\tRefresh interval: %u (", concatHex);
			affichageDureeConvertie(concatHex);
			printf(")");

			// Retry interval
			concatHex = concactQautreOctets(pointeurDNS);
			pointeurDNS += 4;
			printf("\n\tRetry interval: %u (", concatHex);
			affichageDureeConvertie(concatHex);
			printf(")");

			// Expire limit
			concatHex = concactQautreOctets(pointeurDNS);
			pointeurDNS += 4;
			printf("\n\tExpire limit: %u (", concatHex);
			affichageDureeConvertie(concatHex);
			printf(")");

			// Minimum TTL
			concatHex = concactQautreOctets(pointeurDNS);
			pointeurDNS += 4;
			printf("\n\tMinimum TTL: %u (", concatHex);
			affichageDureeConvertie(concatHex);
			printf(")");
		}
	}

	// S'il y a des "Additional"
	if (nbrSupplementaire > 0 && niveauVerbo == COMPLET){
		printf("\nAdditional records:");

		// Réinitialise le buffer
		memset(nomDomaine, 0, sizeof(nomDomaine));

		while (nbrSupplementaire > 0){
			nbrSupplementaire--;

			unsigned int hexa = *pointeurDNS++;

			int tailleNom = 0, retourTaille = 0;
			while (tailleNom < TAILLE_NOM_DOM){
				// On incrémente pour le caractère qui suit dans ce cas
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
			printf("\n\tName: %s", nomDomaine);

			pointeurDNS = affichageInfosAnswer(pointeurDNS);
		}
	}
}