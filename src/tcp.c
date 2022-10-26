#include "../inc/tcp.h"

void gestionTCP(const u_char* paquet, int size_ip){
	const struct tcphdr* tcp = (struct tcphdr*)(paquet + size_ip);

	printf("\n\n");
	titreViolet("TCP");
	printf(JAUNE);
	printf("Port src : %hu\n", ntohs(tcp->th_sport)); // src
	printf("Port dest : %hu\n", ntohs(tcp->th_dport)); // dest
	printf("Num séquence : %u\n", ntohs(tcp->th_seq));
	printf("Num ack : %u\n", ntohs(tcp->th_ack));
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
	printf("\nFenêtre : %hu\n", ntohs(tcp->th_win));
	printf("Checksum : %hu\n", ntohs(tcp->th_sum));
	printf("Pointeur urg : %hu\n", ntohs(tcp->th_urp));

	// Ajout gestion ports (SMTP, FTP, HTTP, ...)
}