#include "ethernet.h"

void affichageMac(const struct ether_header *ethernet, int FlagIO){
	int i;
	unsigned addr;

	if (FlagIO == 0)
		printf("MAC src : ");
	else if (FlagIO == 1)
		printf("MAC dest : ");
	else{
		printf(FIN);
		fprintf(stderr, "|Erreur| Mauvaise valeur du flag IO\n");
		exit(-1);
	}

	for (i = 0; i < 6; i++){
		if (FlagIO == 0)
			addr = (unsigned) ethernet->ether_shost[i];
		else if (FlagIO == 1)
			addr = (unsigned) ethernet->ether_dhost[i];
		
		printf("%.2x", addr);
		if (i < 5)
			printf(":");
	}
	printf("\n");
}

void gestionEthernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* paquet){
	// Titre de second niveau, du paquet
	static int compteurPaquets = 1;
	if (compteurPaquets == 1)
		titreCian("ère trame", compteurPaquets);
	else
		titreCian("ème trame", compteurPaquets);
	compteurPaquets++;

	// Structures pour le paquet
	const struct ether_header* ethernet;
	ethernet = (struct ether_header*)(paquet);

	// Affichage des adresses MAC
	titreViolet("Informations Ethernet");
	printf(ORANGE);
	affichageMac(ethernet, 0); // Adresse src
	affichageMac(ethernet, 1); // Adresse dest
	printf("EtherType : "); // EtherType
	switch(ntohs(ethernet->ether_type)){
		/* PUP protocol */
		case ETHERTYPE_PUP:
			printf("PUP");
			break;

			/* IP protocol */
		case ETHERTYPE_IP:
			printf("IP");
			int size_ethernet = sizeof(struct ether_header);
			gestionIP(paquet, size_ethernet);
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

		/* Protocole non pris en charge */
		default:
			printf("Protocole non pris en charge (%d)", ethernet->ether_type);
			break;
	}
	printf("%s\n\n", FIN);
}