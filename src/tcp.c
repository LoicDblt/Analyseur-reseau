#include "../inc/tcp.h"

int affichageFlag(int nbrFlags, char* nomFlag){
	if (nbrFlags > 0)
		printf(", ");
	else
		printf(" ");
	printf("%s", nomFlag);
	return 1;
}

void gestionTCP(const u_char* paquet, const int offset, int tailleTotale){
	const struct tcphdr* tcp = (struct tcphdr*)(paquet + offset);
	int payload = 0;

	titreProto("TCP", VERT);

	// Ports
	int portSrc = ntohs(tcp->th_sport);
	int portDst = ntohs(tcp->th_dport);

	printf("Src: %u", portSrc);
	sautLigneComplet();

	printf("Dst: %u", portDst);

	if (niveauVerbo > CONCIS){
		sautLigneComplet();

		// Sequence number
		if (niveauVerbo > SYNTHETIQUE)
			printf("Sequence number");
		else
			printf("Seq");

		printf(": %u", ntohl(tcp->th_seq));
		sautLigneComplet();

		// Acknowledgement number
		if (niveauVerbo > SYNTHETIQUE)
			printf("Acknowledgement number");
		else
			printf("Ack");

		printf(": %u", ntohl(tcp->th_ack));
	}

	int tailleHeader = 4*tcp->th_off;

	if (niveauVerbo > SYNTHETIQUE){
		printf("\nHeader length: %d bytes (%d)", tailleHeader,
			tailleHeader/4);

		printf("\nFlags:");
		int nbrFlags = 0;

			/* Urgent */
		if ((tcp->th_flags & TH_URG) > 0)
			nbrFlags += affichageFlag(nbrFlags, "URG");

			/* Acknowledgment */
		if ((tcp->th_flags & TH_ACK) > 0)
			nbrFlags += affichageFlag(nbrFlags, "ACK");

			/* Push */
		if ((tcp->th_flags & TH_PUSH) > 0)
			nbrFlags += affichageFlag(nbrFlags, "PUSH");

			/* Reset */
		if ((tcp->th_flags & TH_RST) > 0)
			nbrFlags += affichageFlag(nbrFlags, "RST");

			/* Syn */
		if ((tcp->th_flags & TH_SYN) > 0)
			nbrFlags += affichageFlag(nbrFlags, "SYN");

			/* Fin */
		if ((tcp->th_flags & TH_FIN) > 0)
			nbrFlags += affichageFlag(nbrFlags, "FIN");

		printf(" (0x%03x)", tcp->th_flags);

		printf("\nWindow: %u\n", ntohs(tcp->th_win));
		printf("Checksum: 0x%04x (Unverified)\n", ntohs(tcp->th_sum));
		printf("Urgent pointer: %u\n", ntohs(tcp->th_urp));

		u_int8_t* pointeurTCPDebutStruct = (u_int8_t*) paquet + offset;
		u_int8_t* pointeurTCP = pointeurTCPDebutStruct + sizeof(struct tcphdr);
		u_int8_t* pointeurTCPFinOptions = pointeurTCPDebutStruct + tailleHeader;
		unsigned int hexUn, hexDeux, hexTrois, hexQuatre, concatHex;

		// Options
		if (pointeurTCP != pointeurTCPFinOptions)
			printf("Options:\n");

		while (pointeurTCP < pointeurTCPFinOptions){
			// On avance ("Type", puis "Longueur" et enfin "Valeur")
			printf("\t");
			unsigned int type = *pointeurTCP++;
			int longueur;

			// "Type" et "Longueur" déjà incrémentés (compris dans longueur)
			if (type == TCPOPT_EOL || type == TCPOPT_NOP)
				longueur = 0;
			else
				longueur = (*pointeurTCP++) - 2;

			switch (type){
				/* End of line */
				case TCPOPT_EOL:
					printf("End of line (%u)", type);
					break;

				/* No-Operations */
				case TCPOPT_NOP:
					printf("No-Operations (%u)", type);
					break;

				/* Maximum segment size */
				case TCPOPT_MAXSEG:
					hexUn = *pointeurTCP++;
					hexDeux = *pointeurTCP++;
					concatHex = (hexUn << 8) | (hexDeux);
					printf("Maximum segment size (%u)", type);
					printf("\n\t\tValue: %u", concatHex);

					// Pointeur déjà avancé
					longueur = 0;
					break;

				/* SACK permitted */
				case TCPOPT_SACK_PERMITTED:
					printf("SACK Permitted (%u)", type);
					break;

				/* Window scale */
				case TCPOPT_WINDOW:
					printf("Window scale (%u)", type);
					printf("\n\t\tShift count: %x (Multiplier 128)",
						*pointeurTCP);
					break;

				/* Timestamp */
				case TCPOPT_TIMESTAMP:
					hexUn = *pointeurTCP++;
					hexDeux = *pointeurTCP++;
					hexTrois = *pointeurTCP++;
					hexQuatre = *pointeurTCP++;
					concatHex = (hexUn << 24) | (hexDeux << 16) |
						(hexTrois << 8) | (hexQuatre);
					printf("Timestamp (%u)", type);
					printf("\n\t\tValue: %u", concatHex);

					hexUn = *pointeurTCP++;
					hexDeux = *pointeurTCP++;
					hexTrois = *pointeurTCP++;
					hexQuatre = *pointeurTCP++;
					concatHex = (hexUn << 24) | (hexDeux << 16) |
						(hexTrois << 8) | (hexQuatre);
					printf("\n\t\tEcho reply: %u", concatHex);

					// Pointeur déjà avancé
					longueur = 0;
					break;

				/* Inconnu */
				default:
					printf("Unknown (%u)", type);
					break;
			}
			printf("\n");

			// On passe au "Type" suivant
			pointeurTCP += longueur;
		}
	}

	payload = tailleTotale - tailleHeader;
	if (niveauVerbo > SYNTHETIQUE)
		printf("Payload: %d", payload);

	// Port FTP
	if (portSrc == PORT_FTP || portDst == PORT_FTP){
		if (niveauVerbo > SYNTHETIQUE)
			printf("\nProtocol: FTP");

		if (payload > 0)
			gestionFTP(paquet, offset + tailleHeader, payload);
	}

	// Port HTTP
	else if (portSrc == PORT_HTTP || portDst == PORT_HTTP){
		if (niveauVerbo > SYNTHETIQUE)
			printf("\nProtocol: HTTP");

		if (payload > 0)
			gestionHTTP(paquet, offset + tailleHeader, payload);
	}

	// Port IMAP
	else if (portSrc == PORT_IMAP || portDst == PORT_IMAP){
		if (niveauVerbo > SYNTHETIQUE)
			printf("\nProtocol: IMAP");

		if (payload > 0)
			gestionIMAP(paquet, offset + tailleHeader, payload);
	}

	// Port POP
	else if (portSrc == PORT_POP || portDst == PORT_POP){
		if (niveauVerbo > SYNTHETIQUE)
			printf("\nProtocol: POP");

		if (payload > 0)
			gestionPOP(paquet, offset + tailleHeader, payload);
	}

	// Ports SMTP
	else if (
		portSrc == PORT_SMTP_1 || portDst == PORT_SMTP_1 ||
		portSrc == PORT_SMTP_2 || portDst == PORT_SMTP_2
	){
		if (niveauVerbo > SYNTHETIQUE)
			printf("\nProtocol: SMTP");

		if (payload > 0)
			gestionSMTP(paquet, offset + tailleHeader, payload);
	}

	// Port Telnet
	else if (portSrc == PORT_TELNET || portDst == PORT_TELNET){
		if (niveauVerbo > SYNTHETIQUE)
			printf("\nProtocol: Telnet");

		if (payload > 0)
			gestionTelnet(paquet, offset + tailleHeader, payload);
	}
}