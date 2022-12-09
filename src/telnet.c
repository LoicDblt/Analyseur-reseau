#include "../inc/telnetHeader.h"

void gestionTelnet(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurTelnet = (u_int8_t*) paquet + offset;

	titreProto("Telnet", ROUGE);

	/**
	 * Source : telnet.h
	 * Si usage de "#define TELCMDS" et "#define TELOPTS", erreurs à la
	 * compilation car tableaux, ci-dessous, définis dans plusieurs objets
	 **/
	char *telopts[NTELOPTS+1] = {
		"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
		"STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP",
		"NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS",
		"NAOVTD", "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
		"DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT",
		"SEND LOCATION", "TERMINAL TYPE", "END OF RECORD",
		"TACACS UID", "OUTPUT MARKING", "TTYLOC",
		"3270 REGIME", "X.3 PAD", "NAWS", "TSPEED", "LFLOW",
		"LINEMODE", "XDISPLOC", "OLD-ENVIRON", "AUTHENTICATION",
		"ENCRYPT", "NEW-ENVIRON",
		0,
	};
	char *telcmds[] = {
		"EOF", "SUSP", "ABORT", "EOR",
		"SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
		"EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC", 0,
	};

	// Affiche le contenu complet du header Telnet
	u_int8_t type, commande, option;
	int compteur_nbr_commandes = 0;

	for (int i = 0; i < tailleHeader; i++){
		type = *pointeurTelnet;

		// Si c'est une commande (Interpret As Command)
		if (type == IAC){
			compteur_nbr_commandes++;

			if (i > 0 && niveauVerbo == SYNTHETIQUE)
				printf(" | ");

			// On indique uniquement qu'une commande a été reçue
			else if (niveauVerbo == CONCIS){
				if (compteur_nbr_commandes == 1)
					printf("Command");

				// On met au pluriels s'il y en a au moins deux
				else if (compteur_nbr_commandes == 2)
					printf("s");
			}

			pointeurTelnet++;
			i++;
			commande = *pointeurTelnet;

			switch (commande){
				/* Will | Won't | Do | Don't */
				case WILL:
				case WONT:
				case DO:
				case DONT:
					pointeurTelnet++;
					i++;
					option = *pointeurTelnet;
					if (niveauVerbo == COMPLET){
						printf("(%d) %s %s\n", commande, TELCMD(commande),
							telopts[option]);
					}
					else if (niveauVerbo == SYNTHETIQUE)
						printf("%s %s", TELCMD(commande), telopts[option]);
					break;

				/* Suboption */
				case SB:
					pointeurTelnet++;
					i++;
					option = *pointeurTelnet;

					if (niveauVerbo == COMPLET){
						printf("(%d) %s %s", commande, TELCMD(commande),
							telopts[option]);
					}
					else if (niveauVerbo == SYNTHETIQUE)
						printf("%s %s", TELCMD(commande),
							telopts[option]);

					pointeurTelnet++;
					i++;
					if (option == TELOPT_TSPEED && niveauVerbo > SYNTHETIQUE)
						printf("\n\tValue: %02d", *pointeurTelnet);
					if (niveauVerbo > SYNTHETIQUE)
						printf("\n");
					break;

				/* Suboption end */
				case SE:
					if (niveauVerbo == COMPLET)
						printf("(%d) %s\n", commande, TELCMD(commande));
					else if (niveauVerbo == SYNTHETIQUE)
						printf("%s", TELCMD(commande));
					break;

				/* Inconnu */
				default:
					if (niveauVerbo == COMPLET)
						printf("(%d) Unknown command", commande);
					else if (niveauVerbo == SYNTHETIQUE)
						printf("Unknown command");
					break;
			}
		}

		// Si ce n'était pas une commande, ce sont des données
		else{
			if (niveauVerbo > CONCIS){
				int retourCara = 0;

				if (i == 0 && niveauVerbo)
					printf("Data: ");

				retourCara = caraCtrl(type);
				if (retourCara == 1 && i < tailleHeader -1)
					printf("\n");
			}
			else if (niveauVerbo == CONCIS && i == 0)
				printf("Data");
		}
		pointeurTelnet++;
	}
}