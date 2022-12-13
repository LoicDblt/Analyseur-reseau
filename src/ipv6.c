#include "../inc/ipv6.h"

void gestionIPv6(const u_char* paquet, const int offset){
	const struct ip6_hdr* ip6 = (struct ip6_hdr*)(paquet + offset);
	char buffAddrIPv6[INET6_ADDRSTRLEN];

	titreProto("IPv6", BLEU);

	if (niveauVerbo == COMPLET){
		printf("Flow info: 0x%06x\n",
			ntohl(ip6->ip6_flow & IPV6_FLOWINFO_MASK));

		printf("Explicit congestion notification: ");
		unsigned int ecn = ntohl(ip6->ip6_flow & IPV6_FLOW_ECN_MASK);
		if (ecn == 0)
			printf("Not ECN-capable transport");
		else
			printf("ECN-capable transport");
		printf(" (%u)\n", ecn);

		printf("Flow label: 0x%06x\n",
			ntohl(ip6->ip6_flow & IPV6_FLOWLABEL_MASK));

		printf("Payload length: %u\n", ntohs(ip6->ip6_plen));
		printf("Hop limit: %u\n", ip6->ip6_hlim);
	}

	// Adresses
	inet_ntop(AF_INET6, &ip6->ip6_src, buffAddrIPv6, INET6_ADDRSTRLEN);
	if (niveauVerbo == COMPLET)
		printf("Source address: ");
	else
		printf("Src: ");
	printf("%s", buffAddrIPv6);
	sautLigneOuSeparateur();

	inet_ntop(AF_INET6, &ip6->ip6_dst, buffAddrIPv6, INET6_ADDRSTRLEN);
	if (niveauVerbo == COMPLET)
		printf("Destination address: ");
	else
		printf("Dst: ");
	printf("%s", buffAddrIPv6);

	// Protocole
	if (niveauVerbo == COMPLET)
		printf("\nNext header: ");
	unsigned int proto = ip6->ip6_nxt;

	switch (proto){
		/* TCP */
		case TCP:
			if (niveauVerbo == COMPLET)
				printf("TCP (%u)", proto);

			gestionTCP(paquet, offset + sizeof(struct ip6_hdr),
				ntohs(ip6->ip6_plen));
			break;

		/* UDP */
		case UDP:
			if (niveauVerbo == COMPLET)
				printf("UDP (%u)", proto);

			gestionUDP(paquet, offset + sizeof(struct ip6_hdr));
			break;

		/* Non pris en charge */
		default:
			if (niveauVerbo == COMPLET)
				printf("Unsupported (%u)", proto);
			break;
	}
	printf(RESET);
}