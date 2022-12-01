#include "../inc/icmp.h"

/** Protocole non implémenté en détail (comme répondu lors d'une question
 * en cours) **/

void gestionICMP(const u_char* paquet, const int offset){
	const struct icmp* icmp = (struct icmp*)(paquet + offset);

	titreProto("ICMP", VERT);

	u_int8_t type = icmp->icmp_type;
	if (niveauVerbo > CONCIS)
		printf("Type: ");
	switch (type){
		/* Echo reply */
		case ICMP_ECHOREPLY:
			if (niveauVerbo > CONCIS)
				printf("%d (Echo reply)", type);
			else
				printf("Echo reply");
			break;

		/* Destination unreachable */
		case ICMP_UNREACH:
			if (niveauVerbo > CONCIS)
				printf("%d (Destination unreachable)", type);
			else
				printf("Destination unreachable");
			break;

		/* Echo request */
		case ICMP_ECHO:
			if (niveauVerbo > CONCIS)
				printf("%d (Echo request)", type);
			else
				printf("Echo request");
			break;

		/* Timestamp request */
		case ICMP_TSTAMP:
			if (niveauVerbo > CONCIS)
				printf("%d (Timestamp request)", type);
			else
				printf("Timestamp request");
			break;

		/* Timestamp reply */
		case ICMP_TSTAMPREPLY:
			if (niveauVerbo > CONCIS)
				printf("%d (Timestamp reply)", type);
			else
				printf("Timestamp reply");
			break;

		/* Traceroute */
		case ICMP_TRACEROUTE:
			if (niveauVerbo > CONCIS)
				printf("%d (Traceroute)", type);
			else
				printf("Traceroute");
			break;

		/* Inconnu */
		default:
			if (niveauVerbo > CONCIS)
				printf("%d (Unknow)", type);
			break;
	}

	if (niveauVerbo > SYNTHETIQUE){
		printf("\nCode: %d\n", icmp->icmp_code);
		printf("Checksum: 0x%04x (Unverified)\n", ntohs(icmp->icmp_cksum));
		printf("Identifier (BE): %d (0x%04x)\n", ntohs(icmp->icmp_id),
			ntohs(icmp->icmp_id));
		printf("Identifier (LE): %d (0x%04x)\n", icmp->icmp_id, icmp->icmp_id);
		printf("Sequence number (BE): %d (0x%04x)\n",  ntohs(icmp->icmp_seq),
			ntohs(icmp->icmp_seq));
		printf("Sequence number (LE): %d (0x%04x)\n", icmp->icmp_seq,
			icmp->icmp_seq);
	}
}