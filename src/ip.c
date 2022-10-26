#include "../inc/ip.h"
#include "../inc/udp.h"
#include "../inc/tcp.h"

void gestionIP(const u_char* paquet, int size_ethernet){
	const struct ip* ip = (struct ip*)(paquet + size_ethernet);

	titreViolet("IP");
	printf(JAUNE);
	printf("IP src : %s\n", inet_ntoa(ip->ip_src)); // src
	printf("IP dest : %s\n", inet_ntoa(ip->ip_dst)); // dest
	printf("Taille header : %d\n", ip->ip_hl);
	printf("Type de service : %d\n", ip->ip_tos);
	printf("Taille : %d\n", ntohs(ip->ip_len));
	printf("Identificateur : %d\n", ntohs(ip->ip_id));
	printf("Offset fragment : %hu\n", ip->ip_off);
	printf("Time to live : %d\n", ip->ip_ttl);
	printf("Checksum : %hu\n", ntohs(ip->ip_sum));
	printf("Protocole de transport : ");
	switch(ip->ip_p){
		/* TCP */
		case 6:
			printf("TCP");
			gestionTCP(paquet, size_ethernet + sizeof(struct ip));
			break;

		/* UDP */
		case 17:
			printf("UDP");
			gestionUDP(paquet, size_ethernet + sizeof(struct ip));
			break;

		/* Protocole non pris en charge */
		default:
			printf("Non pris en charge (%d)", ip->ip_p);
			break;
	}
	printf(RESET);
}