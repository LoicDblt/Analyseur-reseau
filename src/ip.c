#include "../inc/ip.h"

void gestionIP(const u_char* paquet, const int size_ethernet){
	const struct ip* ip = (struct ip*)(paquet + size_ethernet);

	titreViolet("IP");
	printf(JAUNE);

	printf("Src IP : %s\n", inet_ntoa(ip->ip_src));
	printf("Dst IP : %s\n", inet_ntoa(ip->ip_dst));

	printf("Header length : %d\n", ip->ip_hl);
	printf("Type of service : %d\n", ip->ip_tos);
	printf("Total length : %d\n", ntohs(ip->ip_len));
	printf("Identification: 0x%04x\n", ntohs(ip->ip_id));
	printf("Fragment offset : %hu\n", ip->ip_off);
	printf("Time to live : %d\n", ip->ip_ttl);
	printf("Checksum : 0x%04x\n", ntohs(ip->ip_sum));

	printf("Protocol : ");
	switch(ip->ip_p){
		/* TCP */
		case TCP:
			printf("TCP");
			gestionTCP(paquet, size_ethernet + sizeof(struct ip));
			break;

		/* UDP */
		case UDP:
			printf("UDP");
			gestionUDP(paquet, size_ethernet + sizeof(struct ip));
			break;

		/* Protocole non pris en charge */
		default:
			printf("Unsupported (%d)", ip->ip_p);
			break;
	}
	printf(RESET);
}