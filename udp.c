#include "udp.h"

void gestionUDP(const u_char* paquet, int size_ip){
	const struct udphdr* udp;
	udp = (struct udphdr*)(paquet + size_ip);

	ushort portSrc = ntohs(udp->uh_sport);
	ushort portDst = ntohs(udp->uh_dport);

	printf("\n\n");
	titreViolet("Informations UDP");
	printf(JAUNE);
	printf("Port src : %hu\n", portSrc); // src
	printf("Port dest : %hu\n", portDst); // dest
	printf("Taille : %hu\n", ntohs(udp->uh_ulen));
	printf("Checksum : %hu\n", ntohs(udp->uh_sum));

	// Bootp
	if (portSrc == IPPORT_BOOTPS || portDst == IPPORT_BOOTPS){
		printf("Service : Bootp");
		gestionBootp(paquet, size_ip + sizeof(struct udphdr));
	}
}