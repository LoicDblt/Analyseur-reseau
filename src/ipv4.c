#include "../inc/ipv4.h"

void gestionIPv4(const u_char* paquet, const int offset){
	const struct ip* ip = (struct ip*)(paquet + offset);

	titreViolet("IP");

	printf("Version : 4\n");

	printf("Src IP : %s\n", inet_ntoa(ip->ip_src));
	printf("Dst IP : %s", inet_ntoa(ip->ip_dst));

	int tailleHeader = 4*ip->ip_hl;
	if (niveauVerbo > CONCIS){
		printf("\nHeader length : %d bytes (%d)\n", tailleHeader, ip->ip_hl);
		printf("Type of service : %d\n", ntohs(ip->ip_tos));
	}

	int tailleTotale = ntohs(ip->ip_len);
	if (niveauVerbo > CONCIS){
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
			if (niveauVerbo > CONCIS)
				printf("TCP (%d)", proto);

			gestionTCP(paquet, offset + sizeof(struct ip),
				tailleTotale - tailleHeader);
			break;

		/* UDP */
		case UDP:
			if (niveauVerbo > CONCIS)
				printf("UDP (%d)", proto);

			gestionUDP(paquet, offset + sizeof(struct ip));
			break;

		/* Non pris en charge */
		default:
			if (niveauVerbo > CONCIS)
				printf("Unsupported (%d)", proto);
			break;
	}
	printf(RESET);
}