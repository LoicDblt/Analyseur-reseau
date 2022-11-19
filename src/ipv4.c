#include "../inc/ipv4.h"

void gestionIPv4(const u_char* paquet, const int offset){
	const struct ip* ip = (struct ip*)(paquet + offset);

	titreProto("IPv4", BLEU);

	// Adresses IP
	if (niveauVerbo > SYNTHETIQUE)
		printf("Source address: ");
	else
		printf("Src: ");
	printf("%s", inet_ntoa(ip->ip_src));
	sautLigneComplet();


	if (niveauVerbo > SYNTHETIQUE)
		printf("Destination address: ");
	else
		printf("Dst: ");
	printf("%s", inet_ntoa(ip->ip_dst));

	int tailleHeader = 4*ip->ip_hl;
	if (niveauVerbo > SYNTHETIQUE){
		printf("\nHeader length: %d bytes (%u)\n", tailleHeader, ip->ip_hl);

		unsigned int flagsServices = ip->ip_tos;
		printf("Differentiated services field: 0x%02x\n", flagsServices);
		printf("Explicite congestion notification: ");
		/* ECT */

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
	}

	int tailleTotale = ntohs(ip->ip_len);
	if (niveauVerbo > SYNTHETIQUE){
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
		printf("\n       (0x%02x)", flagValue);

		printf("\nFragment offset: %u\n", flagsOff & IP_OFFMASK);
		printf("Time to live: %u\n", ip->ip_ttl);
		printf("Checksum: 0x%04x (Unverified)\n", ntohs(ip->ip_sum));
		printf("Protocol: ");
	}

	unsigned int proto = ip->ip_p;
	switch (proto){
		/* TCP */
		case TCP:
			if (niveauVerbo > SYNTHETIQUE)
				printf("TCP (%u)", proto);

			gestionTCP(paquet, offset + sizeof(struct ip),
				tailleTotale - tailleHeader);
			break;

		/* UDP */
		case UDP:
			if (niveauVerbo > SYNTHETIQUE)
				printf("UDP (%u)", proto);

			gestionUDP(paquet, offset + sizeof(struct ip));
			break;

		/* Non pris en charge */
		default:
			if (niveauVerbo > SYNTHETIQUE)
				printf("Unsupported (%u)", proto);
			break;
	}
	printf(RESET);
}