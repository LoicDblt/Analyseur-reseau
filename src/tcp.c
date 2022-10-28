#include "../inc/tcp.h"

void gestionTCP(const u_char* paquet, const int size_ip){
	const struct tcphdr* tcp = (struct tcphdr*)(paquet + size_ip);

	titreViolet("TCP");
	printf(JAUNE);

	printf("Src port : %hu\n", ntohs(tcp->th_sport));
	printf("Dst port : %hu\n", ntohs(tcp->th_dport));

	printf("Sequence number : %u\n", ntohl(tcp->th_seq));
	printf("Acknowledgement number : %u\n", ntohl(tcp->th_ack));

	printf("Flag : ");
	switch(tcp->th_flags){
		/* URG */
		case TH_URG:
			printf("URG");
			break;

		/* ACK */
		case TH_ACK:
			printf("ACK");
			break;

		/* PUSH */
		case TH_PUSH:
			printf("PSH");
			break;

		/* RST */
		case TH_RST:
			printf("RST");
			break;

		/* SYN */
		case TH_SYN:
			printf("SYN");
			break;

		/* FIN */
		case TH_FIN:
			printf("FIN");
			break;

		/* Pas de flag */
		default:
			printf("Aucun");
			break;
	}

	printf("\nWindow : %hu\n", ntohs(tcp->th_win));
	printf("Checksum : 0x%04x\n", ntohs(tcp->th_sum));
	printf("Urgent pointer : %hu\n", ntohs(tcp->th_urp));

	// Ajout gestion ports (SMTP, FTP, HTTP, ...)
}