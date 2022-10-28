#include "../inc/udp.h"

void gestionUDP(const u_char* paquet, int size_ip){
	const struct udphdr* udp = (struct udphdr*)(paquet + size_ip);

	ushort portSrc = ntohs(udp->uh_sport);
	ushort portDst = ntohs(udp->uh_dport);

	printf("\n\n");
	titreViolet("UDP");
	printf(JAUNE);

	printf("Port src : %hu\n", portSrc);
	printf("Port dest : %hu\n", portDst);

	printf("Taille : %hu\n", ntohs(udp->uh_ulen));
	printf("Checksum : 0x%04x\n", ntohs(udp->uh_sum));

	// Bootp
	if (portSrc == IPPORT_BOOTPS || portDst == IPPORT_BOOTPS){
		printf("Service : Bootp");
		gestionBootP(paquet, size_ip + sizeof(struct udphdr));
	}
}