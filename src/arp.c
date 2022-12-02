#include "../inc/arp.h"

void gestionARP(const u_char* paquet, const int offset){
	const struct arphdr* arp = (struct arphdr*)(paquet + offset);

	titreProto("ARP", BLEU);

	if (niveauVerbo > SYNTHETIQUE){
		// Hardware type
		printf("Hardware type: ");
		switch (ntohs(arp->ar_hrd)){
			/* Ethernet hardware format */
			case ARPHRD_ETHER:
				printf("Ethernet");
				break;

			/* Token-ring hardware format */
			case ARPHRD_IEEE802:
				printf("IEEE802");
				break;

			/* Frame relay hardware format */
			#if __APPLE__ // Noms de constantes différents sur MacOS
				case ARPHRD_FRELAY:
			#else
				case ARPHRD_DLCI:
			#endif
				printf("Frame relay");
				break;

			/* IEEE1394 hardware address */
			case ARPHRD_IEEE1394:
				printf("IEEE1394");
				break;

			/* IEEE1394 EUI-64 */
			#if __APPLE__
				case ARPHRD_IEEE1394_EUI64:
			#else
				case ARPHRD_EUI64:
			#endif
				printf("IEEE1394 EUI64");
				break;

			/* Inconnu */
			default:
				printf("Unknown");
				break;
		}
		printf(" (%u)", ntohs(arp->ar_hrd));

		printf("\nProtocol type: ");
		affichageEtherType(ntohs(arp->ar_pro));

		printf("\nMAC address length: %u\n", arp->ar_hln);
		printf("Protocol address length: %u\n", arp->ar_pln);
	}

	// Opccode
	if (niveauVerbo > CONCIS)
		printf("Opcode: ");
	switch (ntohs(arp->ar_op)){
		/* Request */
		case ARPOP_REQUEST:
			printf("Request");
			break;

		/* Reply */
		case ARPOP_REPLY:
			printf("Reply");
			break;

		/* Revrequest */
		#if __APPLE__
			case ARPOP_REVREQUEST:
		#else
			case ARPOP_RREQUEST:
		#endif
			printf("Revrequest");
			break;

		/* Revreply */
		#if __APPLE__
			case ARPOP_REVREPLY:
		#else
			case ARPOP_RREPLY:
		#endif
			printf("Revreply");
			break;

		/* Invrequest */
		#if __APPLE__
			case ARPOP_INVREQUEST:
		#else
			case ARPOP_InREQUEST:
		#endif
			printf("Invrequest");
			break;

		/* Invreply */
		#if __APPLE__
			case ARPOP_INVREPLY:
		#else
			case ARPOP_InREPLY:
		#endif
			printf("Invreply");
			break;

		/* Inconnu */
		default:
			printf("Unknown");
			break;
	}
	if (niveauVerbo > CONCIS)
		printf(" (%u)", ntohs(arp->ar_op));

	if (niveauVerbo > SYNTHETIQUE){
		u_int8_t* pointeurFinStruct = (u_int8_t*) (paquet + offset +
			sizeof(struct arphdr*));

		printf("\nSrc MAC address: ");
		affichageAdresseMAC(pointeurFinStruct);
		pointeurFinStruct += arp->ar_hln;

		printf("\nSrc IP address: ");
		affichageAdresseIPv4(pointeurFinStruct, arp->ar_pln);
		pointeurFinStruct += arp->ar_pln;

		printf("\nDst MAC address: ");
		affichageAdresseMAC(pointeurFinStruct);
		pointeurFinStruct += arp->ar_hln;

		printf("\nDst IP address: ");
		affichageAdresseIPv4(pointeurFinStruct, arp->ar_pln);
	}
}