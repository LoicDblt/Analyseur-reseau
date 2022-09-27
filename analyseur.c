#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // Masque le warning sur macOS (pcap_lookupdev deprecated)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

// Couleurs pour l'affichage
#define ROUGE	"\033[31m"
#define VERT	"\033[32m"
#define ORANGE	"\033[33m"
#define BLEU	"\033[34m"
#define MAGENTA "\033[35m"
#define CYAN	"\033[36m"
#define JAUNE	"\033[00m"
#define FIN		"\033[00m"

// Fonctions d'affichage des titres
void titreViolet(char* message){
	printf("%s*** %s ***%s\n", MAGENTA, message, FIN);
}
void titreCian(char* message, int compteur){
	if (compteur == -1)
		printf("\n\t%s#### %s ####%s\n", CYAN, message, FIN);
	else
		printf("\n\t%s#### %d%s ####%s\n", CYAN, compteur, message, FIN);
}

// Fonction d'affichage des adresses MAC
// int flagIO : 0 = src / 1 = dest
void affichageMac(const struct ether_header *ethernet, int FlagIO){
	int i;
	unsigned addr;
	printf(ORANGE);
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
	printf("%s\n", FIN);
}

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* paquet){
	// Titre du paquet
	static int compteurPaquets = 1;
	if (compteurPaquets == 1)
		titreCian("ère trame", compteurPaquets);
	else
		titreCian("ème trame", compteurPaquets);

	// Structures pour le paquet
	const struct ether_header *ethernet;
	const struct ip *ip;
	int size_ethernet = sizeof(struct ether_header);
	ethernet = (struct ether_header*)(paquet);
	ip = (struct ip*)(paquet + size_ethernet);

	// Affichage des adresses MAC
	titreViolet("Informations MAC");
	affichageMac(ethernet, 0); // src
	affichageMac(ethernet, 1); // dest
	printf(ORANGE);
	printf("EtherType : %.2x", ntohs(ethernet->ether_type)); // EtherType
	printf("%s\n\n", FIN);

	// Affichage des adresses IP
	titreViolet("Informations IP");
	printf(ORANGE);
	printf("IP src : %s\n", inet_ntoa(ip->ip_src)); // src
	printf("IP dest : %s\n", inet_ntoa(ip->ip_dst)); // dest
	printf(FIN);
	compteurPaquets++;
}

int main(int argc, char *argv[]){
	pcap_t* handle;					/* Session handle */
	char* device;					/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char* paquet;			/* The actual packet */

	// Gestion des commutateurs
	int iFlag = 0, oFlag = 0, fFlag = 0, vFlag = 0;
	int opt, niveau;
	char* nomFichier;
	while ((opt = getopt (argc, argv, "i:o:f:v:")) != -1){
		if (iFlag == 0 && oFlag == 0 && fFlag == 0 && vFlag == 0)
			titreCian("Options activées", -1);
		printf(VERT);

		switch (opt){
			case 'i':
				iFlag = 1;
				if (optarg[0] == '-'){
					fprintf(stderr, "%s|Erreur| Veuillez préciser l'interface (-i)%s\n", ROUGE, FIN);
					return EXIT_FAILURE;
				}
				device = optarg;
				printf("[-i] Interface %s\n", optarg);
				break;

			case 'o':
				oFlag = 1;
				printf("[-o] Fichier offline %s\n", optarg);
				nomFichier = optarg;
				if (access(nomFichier, F_OK) < 0){
					fprintf(stderr, "%s|Erreur| Fichier introuvable%s\n", ROUGE, FIN);
					return EXIT_FAILURE;
				}
				break;

			case 'f':
				fFlag = 1;
				printf("[-f] Filtrage %s\n", optarg);
				break;

			case 'v':
				vFlag = 1;
				niveau = atoi(optarg);
				char* verbosite;
				if (niveau == 1)
					verbosite = "très concis";
				else if (niveau == 2)
					verbosite = "synthétique";
				else if (niveau == 3)
					verbosite = "complet";
				else{
					fprintf(stderr, "%s|Erreur| Niveau de verbosité inconnu (1 [synthétique] à 3 [complet])%s\n", ROUGE, FIN);
					return EXIT_FAILURE;
				}
				printf("[-v] Niveau de verbosité %s [%s]\n", optarg, verbosite);
				break;

			case '?':
				fprintf(stderr, "%s|Erreur| Option \"-%c\" inconnue !%s\n", ROUGE, optopt, FIN);
				return EXIT_FAILURE;

			default:
				return EXIT_FAILURE;
		}
		printf("\033[00m");
	}
	fprintf(stderr, "\033[31m");

	/* Define the device */
	// device = pcap_lookupdev(errbuf);
	// if (device == NULL){
	// 	fprintf(stderr, "|Erreur| Impossible de trouver le périph : %s\n", errbuf);
	// 	return EXIT_FAILURE;
	// }

	/* Cherche les propriétés du périphérique */
	if (pcap_lookupnet(device, &net, &mask, errbuf) < 0){
		fprintf(stderr, "|Erreur| Impossible de récuprer le netmask pour le périph %s: %s\n", device, errbuf);
		net = 0;
		mask = 0;
	}

	/* Ouvre la session en mode "promiscuous" */
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "|Erreur| Impossible d'ouvrir le périph %s: %s\n", device, errbuf);
		return EXIT_FAILURE;
	}

	/* Compile et applique le filtre */
	// if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	// 	fprintf(stderr, "Impossible de passer le filtre %s: %s\n", filter_exp, pcap_geterr(handle));
	// 	return(2);
	// }
	// if (pcap_setfilter(handle, &fp) == -1) {
	// 	fprintf(stderr, "Impossible d'installer le filtre %s: %s\n", filter_exp, pcap_geterr(handle));
	// 	return(2);
	// }

	/* Récupère des paquets */
	if (pcap_loop(handle, 2, callback, NULL) < 0){ // Passer à -1 pour du continu
		fprintf(stderr, "|Erreur| Erreur lors de la lecture du paquet %s\n", device);
		return EXIT_FAILURE;
	}

	/* Ferme la session */
	fprintf(stderr, "\033[00m");
	pcap_close(handle);
	return(EXIT_SUCCESS);
}