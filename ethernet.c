#include "ethernet.h"

// Fonction d'affichage des adresses MAC
// int flagIO : 0 = src / 1 = dest
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

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* paquet){
	// Titre du paquet
	static int compteurPaquets = 1;
	if (compteurPaquets == 1)
		titreCian("ère trame", compteurPaquets);
	else
		titreCian("ème trame", compteurPaquets);
	compteurPaquets++;

	// Structures pour le paquet
	const struct ether_header *ethernet;
	const struct ip *ip;
	int size_ethernet = sizeof(struct ether_header);
	ethernet = (struct ether_header*)(paquet);
	ip = (struct ip*)(paquet + size_ethernet);

	// Affichage des adresses MAC
	titreViolet("Informations MAC");
	printf(ORANGE);
	affichageMac(ethernet, 0); // src
	affichageMac(ethernet, 1); // dest
	printf("EtherType : "); // EtherType
	switch (ntohs(ethernet->ether_type)){
		case ETHERTYPE_PUP: /* PUP protocol */
			printf("PUP");
			break;
		case ETHERTYPE_IP: /* IP protocol */
			printf("IP");
			break;
		case ETHERTYPE_ARP: /* Addr. resolution protocol (ARP) */
			printf("ARP");
			break;
		case ETHERTYPE_REVARP: /* Reverse ARP */
			printf("RevARP");
			break;
		case ETHERTYPE_VLAN: /* IEEE 802.1Q VLAN tagging */
			printf("VLAN");
			break;
		case ETHERTYPE_IPV6: /* IPv6 */
			printf("IPv6");
			break;
		case ETHERTYPE_LOOPBACK: /* Used to test interfaces */
			printf("Loopback");
			break;
		default:
			printf("Protocole inconnu (0x%d)", ethernet->ether_type);
			break;
        }
	printf("%s\n\n", FIN);



	// Affichage des adresses IP (à mettre dans ip.c)
	titreViolet("Informations IP");
	printf(ORANGE);
	printf("IP src : %s\n", inet_ntoa(ip->ip_src)); // src
	printf("IP dest : %s\n", inet_ntoa(ip->ip_dst)); // dest
	printf("%s\n", FIN);
}