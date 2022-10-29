#include "../inc/udp.h"

void gestionUDP(const u_char* paquet, const int size_ip){
	const struct udphdr* udp = (struct udphdr*)(paquet + size_ip);

	ushort portSrc = ntohs(udp->uh_sport);
	ushort portDst = ntohs(udp->uh_dport);

	titreViolet("UDP");
	printf(JAUNE);

	printf("Src port : %u\n", portSrc);
	printf("Dst port : %u\n", portDst);

	printf("Length : %u\n", ntohs(udp->uh_ulen));
	printf("Checksum : 0x%04x (Unverified)\n", ntohs(udp->uh_sum));
	printf("Service : ");

	// BootP
	if (
		portSrc == IPPORT_BOOTPS || portSrc == IPPORT_BOOTPC ||
		portDst == IPPORT_BOOTPS || portDst == IPPORT_BOOTPC
	){
		printf("BootP");
		gestionBootP(paquet, size_ip + sizeof(struct udphdr));
	}
	else{
		printf("Unsupported");
	}
}