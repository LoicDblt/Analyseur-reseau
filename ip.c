#include "ip.h"

void affichageIP(const u_char* paquet, int size_ethernet){
	const struct ip* ip;
	ip = (struct ip*)(paquet + size_ethernet);

	titreViolet("Informations IP");
	printf(ORANGE);
	printf("IP src : %s\n", inet_ntoa(ip->ip_src)); // src
	printf("IP dest : %s", inet_ntoa(ip->ip_dst)); // dest
	printf("%s", FIN);
}