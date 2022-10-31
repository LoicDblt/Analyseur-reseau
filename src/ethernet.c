#include "../inc/ethernet.h"

void affichageAdresseMAC(const u_char* adresse){
	unsigned int addr;
	int typeAddr = 0;

	for (int i = 0; i < MACADDRSIZE; i++){
		addr = (unsigned int) adresse[i];

		// Permet de détecter les "ff"
		if (addr == 255)
			typeAddr++;

		printf("%.2x", addr);
		if (i < 5)
			printf(":");
	}

	if (typeAddr == MACADDRSIZE)
		printf(" (Broadcast)");
}

void affichageEtherType(uint16_t type){
	switch (type){
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

		/* Used to test interfaces */
		case ETHERTYPE_LOOPBACK:
			printf("Loopback");
			break;

		/* Protocole inconnu */
		default:
			printf("Unknown protocol");
			break;
	}
	printf(" (0x%04x)", type);
}

void gestionEthernet(u_char* args, const struct pcap_pkthdr* pkthdr,
	const u_char* paquet
){
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

	// Protocoles pris en charge
	switch (ntohs(ethernet->ether_type)){
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