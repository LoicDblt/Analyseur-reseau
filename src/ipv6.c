#include "../inc/ipv6.h"

void gestionIPv6(const u_char* paquet, const int offset){
	const struct ip6_hdr* ip6 = (struct ip6_hdr*)(paquet + offset);
	char buffAddrIPv6[INET6_ADDRSTRLEN];

	titreViolet("IPv6");

	if (niveauVerbo > SYNTHETIQUE){
		printf("Flow info : 0x%06x\n",
			ntohl(ip6->ip6_flow & IPV6_FLOWINFO_MASK));

		printf("Explicit congestion notification : ");
		unsigned int ecn = ntohl(ip6->ip6_flow & IPV6_FLOW_ECN_MASK);
		if (ecn == 0)
			printf("Not ECN-capable transport");
		else
			printf("ECN-capable transport");
		printf(" (%d)\n", ecn);

		printf("Flow label : 0x%06x\n",
			ntohl(ip6->ip6_flow & IPV6_FLOWLABEL_MASK));

		printf("Payload length : %d\n", ntohs(ip6->ip6_plen));
		printf("Hop limit : %d\n", ip6->ip6_hlim);
	}

	if (niveauVerbo > CONCIS){
		inet_ntop(AF_INET6, &ip6->ip6_src, buffAddrIPv6, INET6_ADDRSTRLEN);
		printf("Src : %s", buffAddrIPv6);
		sautLigneComplet();

		inet_ntop(AF_INET6, &ip6->ip6_dst, buffAddrIPv6, INET6_ADDRSTRLEN);
		printf("Dst : %s", buffAddrIPv6);
	}

	if (niveauVerbo > SYNTHETIQUE)
		printf("\nNext header : ");
	unsigned int proto = ip6->ip6_nxt;

	switch (proto){
		/* TCP */
		case TCP:
			if (niveauVerbo > SYNTHETIQUE)
				printf("TCP (%d)", proto);

			gestionTCP(paquet, offset + sizeof(struct ip6_hdr),
				ntohs(ip6->ip6_plen));
			break;

		/* UDP */
		case UDP:
			if (niveauVerbo > SYNTHETIQUE)
				printf("UDP (%d)", proto);

			gestionUDP(paquet, offset + sizeof(struct ip6_hdr));
			break;

		/* Non pris en charge */
		default:
			if (niveauVerbo > SYNTHETIQUE)
				printf("Unsupported (%d)", proto);
			break;
	}
	printf(RESET);
}