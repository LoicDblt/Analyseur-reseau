#include "../inc/udp.h"

void gestionUDP(const u_char* paquet, const int size_ip){
	const struct udphdr* udp = (struct udphdr*)(paquet + size_ip);

	ushort portSrc = ntohs(udp->uh_sport);
	ushort portDst = ntohs(udp->uh_dport);

	titreViolet("UDP");
	printf(JAUNE);

	printf("Port src : %hu\n", portSrc);
	printf("Port dest : %hu\n", portDst);

	printf("Taille : %hu\n", ntohs(udp->uh_ulen));
	printf("Checksum : 0x%04x\n", ntohs(udp->uh_sum));

	// BootP
	if (
		portSrc == IPPORT_BOOTPS || portSrc == IPPORT_BOOTPC ||
		portDst == IPPORT_BOOTPS || portDst == IPPORT_BOOTPC
	){
		printf("Service : BootP");
		gestionBootP(paquet, size_ip + sizeof(struct udphdr));
	}
	else{
		printf("Service : Non pris en charge");
	}
}