#include "../inc/tcp.h"

void gestionTCP(const u_char* paquet, const int size_ip){
	const struct tcphdr* tcp = (struct tcphdr*)(paquet + size_ip);

	titreViolet("TCP");

	printf("Src port : %u\n", ntohs(tcp->th_sport));
	printf("Dst port : %u\n", ntohs(tcp->th_dport));

	printf("Sequence number : %u\n", ntohl(tcp->th_seq));
	printf("Acknowledgement number : %u\n", ntohl(tcp->th_ack));

	// Impossible de faire un switch pour gérer de multiples flags
	printf("Flags : ");
	if ((tcp->th_flags & TH_FIN) > 0)
		printf("FIN ");
	if ((tcp->th_flags & TH_SYN) > 0)
		printf("SYN ");
	if ((tcp->th_flags & TH_RST) > 0)
		printf("RST ");
	if ((tcp->th_flags & TH_PUSH) > 0)
		printf("PUSH ");
	if ((tcp->th_flags & TH_ACK) > 0)
		printf("ACK ");
	if ((tcp->th_flags & TH_URG) > 0)
		printf("URG ");
	printf("(0x%03x)", tcp->th_flags);

	printf("\nWindow : %u\n", ntohs(tcp->th_win));
	printf("Checksum : 0x%04x (unverified)\n", ntohs(tcp->th_sum));
	printf("Urgent pointer : %u\n", ntohs(tcp->th_urp));

	// Ajout gestion ports (SMTP, FTP, HTTP, ...)
}