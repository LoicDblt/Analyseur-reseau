#include "ip.h"

void gestionIP(const u_char* paquet, int size_ethernet){
	const struct ip* ip;
	ip = (struct ip*)(paquet + size_ethernet);

	titreViolet("Informations IP");
	printf(ORANGE);
	printf("IP src : %s\n", inet_ntoa(ip->ip_src)); // src
	printf("IP dest : %s\n", inet_ntoa(ip->ip_dst)); // dest
	printf("Protocole de transport : ");
	switch(ip->ip_p){
		/* TCP */
		case 6:
			printf("TCP");
			break;

		/* UDP */
		case 17:
			printf("UDP");
			break;

		/* Protocole non pris en charge */
		default:
			printf("Non pris en charge (%d)", ip->ip_p);
			break;
	}
	printf("%s", FIN);
}