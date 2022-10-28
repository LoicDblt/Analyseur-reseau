#include "../inc/arp.h"

void gestionARP(const u_char* paquet, const int size_ethernet){
	const struct arphdr* arp = (struct arphdr*)(paquet + size_ethernet);

	titreViolet("ARP");
	printf(JAUNE);

	printf("Format addr hardware : ");
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
			printf("Inconnu (%u)", ntohs(arp->ar_hrd));
			break;
	}

	printf("\nFormat protocole addr : 0x%04x\n", ntohs(arp->ar_pro));
	printf("Taille addr matérielle : %d\n", arp->ar_hln);
	printf("Taille addr protocole : %d\n", arp->ar_pln);
	printf("Code opération : ");
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
			printf("Inconnu (%d)", ntohs(arp->ar_op));
			break;
	}

	u_int8_t* pointeurStruct = (u_int8_t*) (paquet+size_ethernet+sizeof(struct arphdr*));

	printf("\nAddr matérielle src : ");
	affichageAdresseMac(pointeurStruct);
	pointeurStruct += arp->ar_hln;

	printf("\nAddr IP src : ");
	affichageIP(pointeurStruct, arp->ar_pln);
	pointeurStruct += arp->ar_pln;

	printf("\nAddr matérielle dest : ");
	affichageAdresseMac(pointeurStruct);
	pointeurStruct += arp->ar_hln;

	printf("\nAddr IP dest : ");
	affichageIP(pointeurStruct, arp->ar_pln);
}