#include "../inc/ethernet.h"

void gestionEthernet(u_char* args, const struct pcap_pkthdr* pkthdr,
const u_char* paquet){
	// Titre de second niveau, du paquet
	static unsigned int compteurPaquets = 1;
	int nonPrisCharge = 0;

	if (compteurPaquets == 1)
		titreCian("ère trame", compteurPaquets);
	else
		titreCian("ème trame", compteurPaquets);
	compteurPaquets++;

	// Structures pour le paquet
	const struct ether_header* ethernet;
	ethernet = (struct ether_header*)(paquet);

	// Affichage des adresses MAC
	printf("\033[A\033[A"); // Hack pour retirer les \n du titre (pour le style)
	titreViolet("Ethernet");
	printf(JAUNE);

	printf("MAC src : ");
	affichageAdresseMac(ethernet->ether_shost); // Adresse src
	printf("\nMAC dst : ");
	affichageAdresseMac(ethernet->ether_dhost); // Adresse dest

	printf("\nEtherType : ");
	switch(ntohs(ethernet->ether_type)){
		/* PUP protocol */
		case ETHERTYPE_PUP:
			printf("PUP");
			nonPrisCharge = 1;
			break;

		/* IP protocol */
		case ETHERTYPE_IP:
			printf("IP");
			gestionIP(paquet, sizeof(struct ether_header));
			break;

		/* Addr. resolution protocol (ARP) */
		case ETHERTYPE_ARP:
			printf("ARP");
			gestionARP(paquet, sizeof(struct ether_header));
			break;

		/* Reverse ARP */
		case ETHERTYPE_REVARP:
			printf("RevARP");
			nonPrisCharge = 1;
			break;

		/* IEEE 802.1Q VLAN tagging */
		case ETHERTYPE_VLAN:
			printf("VLAN");
			nonPrisCharge = 1;
			break;

		/* IPv6 */
		case ETHERTYPE_IPV6:
			printf("IPv6");
			nonPrisCharge = 1;
			break;

		/* EAPOL PAE/802.1x */
		case ETHERTYPE_PAE:
			printf("PAE");
			nonPrisCharge = 1;
			break;

		/* 802.11i / RSN Pre-Authentication */
		case ETHERTYPE_RSN_PREAUTH:
			printf("RSN");
			nonPrisCharge = 1;
			break;

		/* IEEE 1588 Precision Time Protocol */
		case ETHERTYPE_PTP:
			printf("PTP");
			nonPrisCharge = 1;
			break;

		/* Used to test interfaces */
		case ETHERTYPE_LOOPBACK:
			printf("Loopback");
			nonPrisCharge = 1;
			break;

		/* Protocole non pris en charge */
		default:
			printf("Protocole non pris en charge (%d)", ethernet->ether_type);
			break;
	}
	if (nonPrisCharge == 1)
		printf("\nNon pris en charge");

	printf("%s\n\n", RESET);
}