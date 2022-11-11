#include "../inc/ethernet.h"

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

void affichageConvertiTimestamp(const struct timeval* tv){
	int retourTaille = 0, offset = 0;
	char buffer[TAILLE_TIMESTAMP];
	struct tm *heureLocale = localtime(&tv->tv_sec);

	retourTaille = strftime(buffer, TAILLE_TIMESTAMP, "%b %d, %Y %H:%M:%S",
		heureLocale);

	if (retourTaille != 0){
		offset = strlen(buffer);
		retourTaille = snprintf(buffer + offset, sizeof(buffer) - offset,
			".%06d", tv->tv_usec);
		verifTaille(retourTaille, sizeof(buffer));
	}
	printf("%s", buffer);
}

void gestionEthernet(u_char* args, const struct pcap_pkthdr* pkthdr,
	const u_char* paquet
){
	// Argument inutilisé
	(void) args;

	// Titre de second niveau, du paquet
	static unsigned int compteurPaquets = 1;
	titreCian("Frame", compteurPaquets);

	// Informations générales sur le paquet
	printf(VIDER_LIGNE); // Hack pour retirer les \n du titre (pour le style)
	titreViolet("General");

	printf("Arrival time : ");
	affichageConvertiTimestamp(&pkthdr->ts);

	// Structures pour le paquet
	const struct ether_header* ethernet;
	ethernet = (struct ether_header*)(paquet);

	// Affichage des adresses MAC
	titreViolet("Ethernet");

	printf("Src MAC : ");
	affichageAdresseMAC(ethernet->ether_shost); // Adresse src
	printf("\nDst MAC : ");
	affichageAdresseMAC(ethernet->ether_dhost); // Adresse dest

	printf("\nEtherType : ");
	affichageEtherType(ntohs(ethernet->ether_type));

	// Protocoles pris en charge
	switch (ntohs(ethernet->ether_type)){
		/* IP */
		case ETHERTYPE_IP:
			gestionIP(paquet, sizeof(struct ether_header));
			break;

		/* ARP */
		case ETHERTYPE_ARP:
			gestionARP(paquet, sizeof(struct ether_header));
			break;

		/* Non pris en charge */
		default:
			printf("\nUnsupported protocol");
			break;
	}

	printf("%s\n\n", RESET);
	compteurPaquets++;
}