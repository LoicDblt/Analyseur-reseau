#include "../inc/telnetHeader.h"

void gestionTelnet(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurTelnet = (u_int8_t*) paquet + offset;

	titreProto("Telnet", ROUGE);

	// Source : telnet.h (erreur d'import (avec arp.o) depuis le header...)
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
	for (int i = 0; i < tailleHeader; i++){
		type = *pointeurTelnet;

		// Si c'est une commande
		if (type == COMMANDE){
			if (i > 0 && niveauVerbo == SYNTHETIQUE)
				printf(" | ");
			else if (i == 0 && niveauVerbo == CONCIS)
				printf("Commands");

			pointeurTelnet++;
			i++;
			commande = *pointeurTelnet;

			switch (commande){
				/* WILL | WON'T | DO | DON'T */
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

				/* SUBOPTION */
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

				/* SUBOPTION END */
				case SE:
					if (niveauVerbo == COMPLET)
						printf("(%d) %s\n", commande, TELCMD(commande));
					else if (niveauVerbo == SYNTHETIQUE)
						printf("%s", TELCMD(commande));
					break;

				/* Inconnu */
				default:
					printf("(%d) Unknown command\n", commande);
					break;
			}
		}

		// Si ce n'était pas une commande, ce sont des données
		else{
			if (niveauVerbo > CONCIS){
				if (i == 0 && niveauVerbo)
					printf("Data: ");
				caraCtrl(type);
			}
			else if (niveauVerbo == CONCIS && i == 0)
				printf("Data");
		}
		pointeurTelnet++;
	}
}