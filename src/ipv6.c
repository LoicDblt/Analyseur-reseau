#include "../inc/ipv6.h"

void gestionIPv6(const u_char* paquet, const int offset){
	const struct ip6_hdr* ip6 = (struct ip6_hdr*)(paquet + offset);

	titreViolet("IPv6");

	char buffAddrIPv6[INET6_ADDRSTRLEN];

	printf("Flow info : 0x%06x\n",
		ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow & IPV6_FLOWINFO_MASK));

	printf("Explicit congestion notification : ");
	unsigned int ecn = ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow &
		IPV6_FLOW_ECN_MASK);
	if (ecn == 0)
		printf("Not ECN-capable transport");
	else
		printf("ECN-capable transport");
	printf(" (%d)\n", ecn);

	printf("Flow label : 0x%06x\n",
		ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow & IPV6_FLOWLABEL_MASK));
	printf("Payload length : %d\n", ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
	printf("Hop limit : %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

	inet_ntop(AF_INET6, &ip6->ip6_src, buffAddrIPv6, INET6_ADDRSTRLEN);
	printf("Src IP : %s\n", buffAddrIPv6);
	inet_ntop(AF_INET6, &ip6->ip6_dst, buffAddrIPv6, INET6_ADDRSTRLEN);
	printf("Dest IP : %s\n", buffAddrIPv6);

	printf("Next header : ");
	unsigned int proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	switch (proto){
		/* TCP */
		case TCP:
			printf("TCP (%d)", proto);
			gestionTCP(paquet, offset + sizeof(struct ip6_hdr),
				ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
			break;

		/* UDP */
		case UDP:
			printf("UDP (%d)", proto);
			gestionUDP(paquet, offset + sizeof(struct ip6_hdr));
			break;

		/* Non pris en charge */
		default:
			printf("Unsupported (%d)", proto);
			break;
	}
	printf(RESET);
}