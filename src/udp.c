#include "../inc/udp.h"

void gestionUDP(const u_char* paquet, const int offset){
	const struct udphdr* udp = (struct udphdr*)(paquet + offset);

	ushort portSrc = ntohs(udp->uh_sport);
	ushort portDst = ntohs(udp->uh_dport);

	titreProto("UDP", VERT);

	// Ports
	printf("Src: %u", portSrc);
	sautLigneOuSeparateur();

	printf("Dst: %u", portDst);

	if (niveauVerbo == COMPLET){
		unsigned int tailleTotale = ntohs(udp->uh_ulen);
		printf("\nLength: %u\n", tailleTotale);
		printf("Checksum: 0x%04x (Unverified)\n", ntohs(udp->uh_sum));
		printf("Payload: %lu\n", tailleTotale - sizeof(struct udphdr));
	}

	// Ports BootP
	if (
		portSrc == IPPORT_BOOTPS || portSrc == IPPORT_BOOTPC ||
		portDst == IPPORT_BOOTPS || portDst == IPPORT_BOOTPC
	){
		if (niveauVerbo == COMPLET)
			printf("Protocol: BootP");

		gestionBootP(paquet, offset + sizeof(struct udphdr));
	}

	// Port DNS
	else if (portSrc == PORT_DNS || portDst == PORT_DNS){
		if (niveauVerbo == COMPLET)
			printf("Protocol: DNS");

		gestionDNS(paquet, offset + sizeof(struct udphdr));
	}
}