#include "../inc/ethernet.h"

void affichageAdresseMAC(const u_char* adresse){
	int i;
	unsigned addr;

	for (i = 0; i < 6; i++){
		addr = (unsigned) adresse[i];

		printf("%.2x", addr);
		if (i < 5)
			printf(":");
	}
}

void affichageEtherType(uint16_t type){
	switch(type){
		/* PUP protocol */
		case ETHERTYPE_PUP:
			printf("PUP");
			break;

		/* IP protocol */
		case ETHERTYPE_IP:
			printf("IP");
			break;

		/* Addr. resolution protocol (ARP) */
		case ETHERTYPE_ARP:
			printf("ARP");
			break;

		/* Reverse ARP */
		case ETHERTYPE_REVARP:
			printf("RevARP");
			break;

		/* IEEE 802.1Q VLAN tagging */
		case ETHERTYPE_VLAN:
			printf("VLAN");
			break;

		/* IPv6 */
		case ETHERTYPE_IPV6:
			printf("IPv6");
			break;

		/* EAPOL PAE/802.1x */
		case ETHERTYPE_PAE:
			printf("PAE");
			break;

		/* 802.11i / RSN Pre-Authentication */
		case ETHERTYPE_RSN_PREAUTH:
			printf("RSN");
			break;

		/* IEEE 1588 Precision Time Protocol */
		case ETHERTYPE_PTP:
			printf("PTP");
			break;

		/* Used to test interfaces */
		case ETHERTYPE_LOOPBACK:
			printf("Loopback");
			break;

		/* Protocole non pris en charge */
		default:
			printf("Unsupported protocol (%d)", type);
			break;
	}
}

void gestionEthernet(u_char* args, const struct pcap_pkthdr* pkthdr,
const u_char* paquet){
	// Titre de second niveau, du paquet
	static unsigned int compteurPaquets = 1;

	titreCian("Frame", compteurPaquets);
	compteurPaquets++;

	// Structures pour le paquet
	const struct ether_header* ethernet;
	ethernet = (struct ether_header*)(paquet);

	// Affichage des adresses MAC
	printf("\033[A\033[A"); // Hack pour retirer les \n du titre (pour le style)
	titreViolet("Ethernet");
	printf(JAUNE);

	printf("Src MAC : ");
	affichageAdresseMAC(ethernet->ether_shost); // Adresse src
	printf("\nDst MAC : ");
	affichageAdresseMAC(ethernet->ether_dhost); // Adresse dest

	printf("\nEtherType : ");
	affichageEtherType(ntohs(ethernet->ether_type));

	switch(ntohs(ethernet->ether_type)){
		case ETHERTYPE_IP:
			gestionIP(paquet, sizeof(struct ether_header));
			break;

		case ETHERTYPE_ARP:
			gestionARP(paquet, sizeof(struct ether_header));
			break;
		
		default:
			printf("\nUnsupported protocol");
			break;
	}

	printf("%s\n\n", RESET);
}