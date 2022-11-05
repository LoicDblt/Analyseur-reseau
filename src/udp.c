#include "../inc/udp.h"

void gestionUDP(const u_char* paquet, const int offset){
	const struct udphdr* udp = (struct udphdr*)(paquet + offset);

	ushort portSrc = ntohs(udp->uh_sport);
	ushort portDst = ntohs(udp->uh_dport);

	titreViolet("UDP");

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
		gestionBootP(paquet, offset + sizeof(struct udphdr));
	}
	else if (portSrc == PORT_DNS || portDst == PORT_DNS){
		printf("DNS");
		gestionDNS(paquet, offset + sizeof(struct udphdr));
	}
	else{
		printf("Unsupported");
	}
}