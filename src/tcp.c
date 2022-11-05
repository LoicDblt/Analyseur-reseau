#include "../inc/tcp.h"

void gestionTCP(const u_char* paquet, const int offset){
	const struct tcphdr* tcp = (struct tcphdr*)(paquet + offset);

	titreViolet("TCP");

	int portSrc = ntohs(tcp->th_sport);
	int portDst = ntohs(tcp->th_dport);
	printf("Src port : %u\n", portSrc);
	printf("Dst port : %u\n", portDst);

	printf("Sequence number : %u\n", ntohl(tcp->th_seq));
	printf("Acknowledgement number : %u\n", ntohl(tcp->th_ack));

	int tailleHeader = 4*tcp->th_off;
	printf("Header length : %d bytes (%d)\n", tailleHeader, tailleHeader/4);

	// Impossible de faire un switch pour gérer de multiples flags
	printf("Flags : ");
	if ((tcp->th_flags & TH_FIN) > 0)
		printf("FIN ");
	if ((tcp->th_flags & TH_SYN) > 0)
		printf("SYN ");
	if ((tcp->th_flags & TH_RST) > 0)
		printf("RST ");
	if ((tcp->th_flags & TH_PUSH) > 0)
		printf("PUSH ");
	if ((tcp->th_flags & TH_ACK) > 0)
		printf("ACK ");
	if ((tcp->th_flags & TH_URG) > 0)
		printf("URG ");
	printf("(0x%03x)", tcp->th_flags);

	printf("\nWindow : %u\n", ntohs(tcp->th_win));
	printf("Checksum : 0x%04x (Unverified)\n", ntohs(tcp->th_sum));
	printf("Urgent pointer : %u\n", ntohs(tcp->th_urp));

	u_int8_t* pointeurTCPDebutStruct = (u_int8_t*) paquet + offset;
	u_int8_t* pointeurTCP = pointeurTCPDebutStruct + sizeof(struct tcphdr);
	u_int8_t* pointeurTCPFinOptions = pointeurTCPDebutStruct + tailleHeader;
	unsigned int hexUn, hexDeux, hexTrois, hexQuatre, concatHex;
	printf("Options :\n");

	while (pointeurTCP < pointeurTCPFinOptions){
		// On avance ("Type", puis "Longueur" et enfin "Valeur")
		printf("\t");
		int type = *pointeurTCP++;
		int longueur;

		// "Type" et "Longueur" sont déjà incrémentés (compris dans longueur)
		if (type == TCPOPT_EOL || type == TCPOPT_NOP)
			longueur = 0;
		else
			longueur = (*pointeurTCP++) - 2;

		switch (type){
			/* End of line */
			case TCPOPT_EOL:
				printf("End of line (%d)", type);
				break;

			/* No-Operations */
			case TCPOPT_NOP:
				printf("No-Operations (%d)", type);
				break;

			/* Maximum segment size */
			case TCPOPT_MAXSEG:
				hexUn = *pointeurTCP++;
				hexDeux = *pointeurTCP++;
				concatHex = (hexUn << 8) | (hexDeux);
				printf("Maximum segment size (%d)", type);
				printf("\n\t\tValue : %d", concatHex);

				// Pointeur déjà avancé
				longueur = 0;
				break;

			/* SACK permitted */
			case TCPOPT_SACK_PERMITTED:
				printf("SACK Permitted (%d)", type);
				break;

			/* Window scale */
			case TCPOPT_WINDOW:
				printf("Window scale (%d)", type);
				printf("\n\t\tShift count : %x (Multiplier 128)", *pointeurTCP);
				break;

			/* Timestamp */
			case TCPOPT_TIMESTAMP:
				hexUn = *pointeurTCP++;
				hexDeux = *pointeurTCP++;
				hexTrois = *pointeurTCP++;
				hexQuatre = *pointeurTCP++;
				concatHex = (hexUn << 24) | (hexDeux << 16) | (hexTrois << 8) |
					(hexQuatre);
				printf("Timestamp (%d)", type);
				printf("\n\t\tValue : %d", concatHex);

				// Pointeur déjà avancé
				longueur = 4;
				break;

			/* Inconnu */
			default:
				printf("Unknown (%d)", type);
				break;
		}
		printf("\n");

		// On passe au "Type" suivant
		pointeurTCP += longueur;
	}

	// Ports SMTP
	if (
		portSrc == PORT_SMTP_1 || portDst == PORT_SMTP_1 ||
		portSrc == PORT_SMTP_2 || portDst == PORT_SMTP_2
	){
		printf("Protocol : SMTP");
		gestionSMTP(paquet, offset + tailleHeader);
	}
	if (portSrc == PORT_SMTP_TLS || portDst == PORT_SMTP_TLS)
		printf("Protocol : SMTP TLS (Unsupported)");
}