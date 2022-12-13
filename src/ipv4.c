#include "../inc/ipv4.h"

void gestionIPv4(const u_char* paquet, const int offset){
	const struct ip* ip = (struct ip*)(paquet + offset);

	titreProto("IPv4", BLEU);

	int tailleHeader = 4*ip->ip_hl;
	int tailleTotale = ntohs(ip->ip_len);

	if (niveauVerbo == COMPLET){
		printf("Header length: %d bytes (%u)\n", tailleHeader, ip->ip_hl);

		unsigned int flagsServices = ip->ip_tos;
		printf("Differentiated services field: 0x%02x\n", flagsServices);

		// ECN
		printf("Explicite congestion notification: ");

		if ((flagsServices & IPTOS_ECN_MASK) > 0){
			/* ECN-capable transport (1) */
			if ((flagsServices & IPTOS_ECN_ECT1) > 0)
				printf("ECN-capable transport (1)");

			/* ECN-capable transport (0) */
			if ((flagsServices & IPTOS_ECN_ECT0) > 0)
				printf("ECN-capable transport (0)");
		}
		else{
			printf("Not ECN-capable transport (%d)",
				flagsServices & IPTOS_ECN_MASK);
		}

		printf("\nTotal length: %d\n", tailleTotale);

		printf("Identification: 0x%04x (%u)\n", ntohs(ip->ip_id),
			ntohs(ip->ip_id));

		unsigned int flagsOff = ntohs(ip->ip_off);
		unsigned int flagValue = 0;
		printf("Flags: ");

		/* Reserved bit */
		if ((flagsOff & IP_RF) > 0){
			printf("Reserved bit ");
			flagValue += 4;
		}

		/* Don't fragment */
		if ((flagsOff & IP_DF) > 0){
			printf("Don't fragment ");
			flagValue += 2;
		}

		/* More fragments */
		if ((flagsOff & IP_RF) > 0){
			printf("More fragments ");
			flagValue += 1;
		}
		printf("(0x%02x)", flagValue);

		printf("\nFragment offset: %u\n", flagsOff & IP_OFFMASK);
		printf("Time to live: %u\n", ip->ip_ttl);
		printf("Checksum: 0x%04x (Unverified)\n", ntohs(ip->ip_sum));
	}

	// Adresses
	char* ipSrc = strdup(inet_ntoa(ip->ip_src));
	char* ipDst = strdup(inet_ntoa(ip->ip_dst));
	afficheSrcDstAddrIP(ipSrc, ipDst);

	// Protocole
	if (niveauVerbo == COMPLET)
		printf("\nProtocol: ");
	unsigned int proto = ip->ip_p;

	switch (proto){
		/* ICMP */
		case ICMP:
			if (niveauVerbo == COMPLET)
				printf("ICMP (%u)", proto);

			gestionICMP(paquet, offset + tailleHeader);
			break;

		/* TCP */
		case TCP:
			if (niveauVerbo == COMPLET)
				printf("TCP (%u)", proto);

			gestionTCP(paquet, offset + tailleHeader,
				tailleTotale - tailleHeader);
			break;

		/* UDP */
		case UDP:
			if (niveauVerbo == COMPLET)
				printf("UDP (%u)", proto);

			gestionUDP(paquet, offset + tailleHeader);
			break;

		/* Non pris en charge */
		default:
			if (niveauVerbo == COMPLET)
				printf("Unsupported (%u)", proto);
			break;
	}
	printf(RESET);
}