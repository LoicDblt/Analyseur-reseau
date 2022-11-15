#include "../inc/ipv4.h"

void gestionIPv4(const u_char* paquet, const int offset){
	const struct ip* ip = (struct ip*)(paquet + offset);

	titreViolet("IPv4");

	// Adresses IP
	if (niveauVerbo > CONCIS){
		printf("Src : %s", inet_ntoa(ip->ip_src));
		sautLigneComplet();

		printf("Dst : %s", inet_ntoa(ip->ip_dst));
	}

	int tailleHeader = 4*ip->ip_hl;
	if (niveauVerbo > SYNTHETIQUE){
		printf("\nHeader length : %d bytes (%d)\n", tailleHeader, ip->ip_hl);
		printf("Type of service : %d\n", ntohs(ip->ip_tos));
	}

	int tailleTotale = ntohs(ip->ip_len);
	if (niveauVerbo > SYNTHETIQUE){
		printf("Total length : %d\n", tailleTotale);

		printf("Identification: 0x%04x (%d)\n", ntohs(ip->ip_id),
			ntohs(ip->ip_id));
		printf("Fragment offset : %u\n", ip->ip_off);
		printf("Time to live : %d\n", ip->ip_ttl);
		printf("Checksum : 0x%04x (Unverified)\n", ntohs(ip->ip_sum));
		printf("Protocol : ");
	}

	unsigned int proto = ip->ip_p;
	switch (proto){
		/* TCP */
		case TCP:
			if (niveauVerbo > SYNTHETIQUE)
				printf("TCP (%d)", proto);

			gestionTCP(paquet, offset + sizeof(struct ip),
				tailleTotale - tailleHeader);
			break;

		/* UDP */
		case UDP:
			if (niveauVerbo > SYNTHETIQUE)
				printf("UDP (%d)", proto);

			gestionUDP(paquet, offset + sizeof(struct ip));
			break;

		/* Non pris en charge */
		default:
			if (niveauVerbo > SYNTHETIQUE)
				printf("Unsupported (%d)", proto);
			break;
	}
	printf(RESET);
}