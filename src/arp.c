#include "../inc/arp.h"

void gestionARP(const u_char* paquet, const int size_ethernet){
	const struct arphdr* arp = (struct arphdr*)(paquet + size_ethernet);

	titreViolet("ARP");
	printf(JAUNE);

	printf("Hardware  type : ");
	switch(ntohs(arp->ar_hrd)){
		/* Ethernet hardware format */
		case ARPHRD_ETHER:
			printf("Ethernet");
			break;

		/* Token-ring hardware format */
		case ARPHRD_IEEE802:
			printf("IEEE802");
			break;

		/* Frame relay hardware format */
		case ARPHRD_FRELAY:
			printf("Frame relay");
			break;

		/* IEEE1394 hardware address */
		case ARPHRD_IEEE1394:
			printf("IEEE1394");
			break;

		/* IEEE1394 EUI-64 */
		case ARPHRD_IEEE1394_EUI64:
			printf("IEEE1394 EUI64");
			break;

		/* Inconnu */
		default:
			printf("Unknown");
			break;
	}
	printf(" (%u)", ntohs(arp->ar_hrd));

	printf("\nProtocol type : ");
	affichageEtherType(ntohs(arp->ar_pro));
	printf("\nMAC address length : %d\n", arp->ar_hln);
	printf("Protocol address length : %d\n", arp->ar_pln);

	printf("Opcode : ");
	switch(ntohs(arp->ar_op)){
		/* Request */
		case ARPOP_REQUEST:
			printf("Request");
			break;

		/* Reply */
		case ARPOP_REPLY:
			printf("Reply");
			break;

		/* Revrequest */
		case ARPOP_REVREQUEST:
			printf("Revrequest");
			break;

		/* Revreply */
		case ARPOP_REVREPLY:
			printf("Revreply");
			break;

		/* Invrequest */
		case ARPOP_INVREQUEST:
			printf("Invrequest");
			break;

		/* Invreply */
		case ARPOP_INVREPLY:
			printf("Invreply");
			break;

		default:
			printf("Unknown");
			break;
	}
	printf(" (%u)", ntohs(arp->ar_op));

	u_int8_t* pointeurFinStruct = (u_int8_t*) (paquet + size_ethernet +
		sizeof(struct arphdr*));

	printf("\nSrc MAC address: ");
	affichageAdresseMAC(pointeurFinStruct);
	pointeurFinStruct += arp->ar_hln;

	printf("\nSrc IP address : ");
	affichageIP(pointeurFinStruct, arp->ar_pln);
	pointeurFinStruct += arp->ar_pln;

	printf("\nDst MAC address : ");
	affichageAdresseMAC(pointeurFinStruct);
	pointeurFinStruct += arp->ar_hln;

	printf("\nDst IP address : ");
	affichageIP(pointeurFinStruct, arp->ar_pln);
}