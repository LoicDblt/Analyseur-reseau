#include "../inc/ipv6.h"

void gestionIPv6(const u_char* paquet, const int offset){
	titreViolet("IPv6");
	const struct ip6_hdr* ip6 = (struct ip6_hdr*)(paquet + offset);
	char buff[INET6_ADDRSTRLEN];

	printf("Flow : 0x%06x\n",
		(ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & MASQUE));
	printf("Payload length : %d\n", ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
	printf("Hop limit : %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

	inet_ntop(AF_INET6, &ip6->ip6_src, buff, INET6_ADDRSTRLEN);
	printf("Src IP : %s\n", buff);
	inet_ntop(AF_INET6, &ip6->ip6_dst, buff, INET6_ADDRSTRLEN);
	printf("Dest IP : %s\n", buff);

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