#include "../inc/ip.h"

void gestionIP(const u_char* paquet, const int offset, int type){
	switch (type){
		/* IPv4 */
		case ETHERTYPE_IP:
			titreViolet("IP");
			const struct ip* ip = (struct ip*)(paquet + offset);

			printf("Src IP : %s\n", inet_ntoa(ip->ip_src));
			printf("Dst IP : %s\n", inet_ntoa(ip->ip_dst));

			int tailleHeader = 4*ip->ip_hl;
			printf("Header length : %d bytes (%d)\n", tailleHeader, ip->ip_hl);
			printf("Type of service : %d\n", ntohs(ip->ip_tos));

			int tailleTotale = ntohs(ip->ip_len);
			printf("Total length : %d\n", tailleTotale);

			printf("Identification: 0x%04x (%d)\n", ntohs(ip->ip_id),
				ntohs(ip->ip_id));
			printf("Fragment offset : %u\n", ip->ip_off);
			printf("Time to live : %d\n", ip->ip_ttl);
			printf("Checksum : 0x%04x (Unverified)\n", ntohs(ip->ip_sum));

			printf("Protocol : ");
			unsigned int proto = ip->ip_p;
			switch (proto){
				/* TCP */
				case TCP:
					printf("TCP (%d)", proto);
					gestionTCP(paquet, offset + sizeof(struct ip),
						tailleTotale - tailleHeader);
					break;

				/* UDP */
				case UDP:
					printf("UDP (%d)", proto);
					gestionUDP(paquet, offset + sizeof(struct ip));
					break;

				/* Non pris en charge */
				default:
					printf("Unsupported (%d)", proto);
					break;
			}
			break;

		/* IPv6 */
		case ETHERTYPE_IPV6:
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
			unsigned int proto6 = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
			switch (proto6){
				/* TCP */
				case TCP:
					printf("TCP (%d)", proto6);
					gestionTCP(paquet, offset + sizeof(struct ip6_hdr),
						ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
					break;

				/* UDP */
				case UDP:
					printf("UDP (%d)", proto6);
					gestionUDP(paquet, offset + sizeof(struct ip6_hdr));
					break;

				/* Non pris en charge */
				default:
					printf("Unsupported (%d)", proto6);
					break;
			}
			break;

		/* Inconnu (ne doit pas arriver) */
		default:
			break;
	}
	printf(RESET);
}