#include "../inc/ip.h"

void gestionIP(const u_char* paquet, const int offset){
	const struct ip* ip = (struct ip*)(paquet + offset);

	titreViolet("IP");

	printf("Src IP : %s\n", inet_ntoa(ip->ip_src));
	printf("Dst IP : %s\n", inet_ntoa(ip->ip_dst));

	int tailleHeader = 4*ip->ip_hl;
	printf("Header length : %d\n", tailleHeader);
	printf("Type of service : %d\n", ntohs(ip->ip_tos));

	int tailleTotale = ntohs(ip->ip_len);
	printf("Total length : %d\n", tailleTotale);

	printf("Identification: 0x%04x (%d)\n", ntohs(ip->ip_id), ntohs(ip->ip_id));
	printf("Fragment offset : %u\n", ip->ip_off);
	printf("Time to live : %d\n", ip->ip_ttl);
	printf("Checksum : 0x%04x (Unverified)\n", ntohs(ip->ip_sum));

	printf("Protocol : ");
	unsigned int proto = ip->ip_p;
	switch (proto){
		/* TCP */
		case TCP:
			printf("TCP (%d)", proto);
			gestionTCP(paquet, offset + sizeof(struct ip),
				tailleTotale - tailleHeader);
			break;

		/* UDP */
		case UDP:
			printf("UDP (%d)", proto);
			gestionUDP(paquet, offset + sizeof(struct ip));
			break;

		/* Non pris en charge */
		default:
			printf("Unsupported (%d)", proto);
			break;
	}
	printf(RESET);
}