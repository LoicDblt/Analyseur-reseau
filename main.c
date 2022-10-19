#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // Masque le warning "pcap_lookupdev deprecated"

#include <unistd.h>
#include <pcap.h>

#include "utile.h"
#include "ethernet.h"

int main(int argc, char *argv[]){
	pcap_t* handle;					/* Session handle */
	char* device = "";				/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	char* filter_exp = "";	/* The filter expression */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char* paquet;			/* The actual packet */

	// Gestion des commutateurs
	int iFlag = 0, oFlag = 0, fFlag = 0, vFlag = 0;
	int opt, niveau;
	char* nomFichier;

	while((opt = getopt (argc, argv, "i:o:f:v:")) != -1){
		if (iFlag == 0 && oFlag == 0 && fFlag == 0 && vFlag == 0)
			titreCian("Options activées", -1);
		printf(VERT);

		switch(opt){
			case 'i': // Interface
				iFlag = 1;
				if (optarg[0] == '-'){
					fprintf(stderr, "%s|Erreur| Veuillez préciser l'interface (-i)%s\n", ROUGE, RESET);
					return EXIT_FAILURE;
				}
				device = optarg;
				printf("[-i] Interface %s\n", optarg);
				break;

			case 'o': // Fichier offline
				oFlag = 1;
				printf("[-o] Fichier offline %s\n", optarg);
				nomFichier = optarg;
				if (access(nomFichier, F_OK) < 0){
					fprintf(stderr, "%s|Erreur| Fichier introuvable%s\n", ROUGE, RESET);
					return EXIT_FAILURE;
				}
				break;

			case 'f': // Filtrage
				fFlag = 1;
				printf("[-f] Filtrage %s\n", optarg);
				filter_exp = optarg;
				break;

			case 'v': // Verbosité
				vFlag = 1;
				niveau = atoi(optarg);
				char* verbosite;
				switch(niveau){
					case 1:
						verbosite = "très concis";
						break;

					case 2:
						verbosite = "synthétique";
						break;

					case 3:
						verbosite = "complet";
						break;

					default:
						fprintf(stderr, "%s|Erreur| Niveau de verbosité inconnu (1 [très concis] à 3 [complet])%s\n", ROUGE, RESET);
						return EXIT_FAILURE;
				}
				printf("[-v] Niveau de verbosité %s [%s]\n", optarg, verbosite);
				break;

			case '?':
				fprintf(stderr, "%s|Erreur| Option \"-%c\" inconnue%s\n", ROUGE, optopt, RESET);
				return EXIT_FAILURE;

			default:
				return EXIT_FAILURE;
		}
		printf(RESET);
	}
	fprintf(stderr, "%s\n", ROUGE);

	/* Défini l'interface si elle ne l'a pas été avec un commutateur */
	if (device == NULL || device[0] == '\0')
		device = pcap_lookupdev(errbuf);
	if (device == NULL){
		fprintf(stderr, "|Erreur| Impossible de trouver le périphérique : %s\n", errbuf);
		return EXIT_FAILURE;
	}

	/* Cherche les propriétés de l'interface */
	if (pcap_lookupnet(device, &net, &mask, errbuf) < 0){
		fprintf(stderr, "|Erreur| Impossible de récuprer le netmask pour l'interface %s: %s\n", device, errbuf);
		net = 0;
		mask = 0;
	}

	/* Ouvre la session en mode "promiscuous" */
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "|Erreur| Impossible d'ouvrir l'interface %s: %s\n", device, errbuf);
		return EXIT_FAILURE;
	}

	/* Compile et applique le filtre */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Impossible de passer le filtre %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Impossible d'installer le filtre %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* Récupère des paquets */
	if (pcap_loop(handle, 3, gestionEthernet, NULL) < 0){ // Passer l'argument à -1 pour du continu
		fprintf(stderr, "|Erreur| Erreur lors de la lecture du paquet %s\n", device);
		return EXIT_FAILURE;
	}

	/* Ferme la session */
	fprintf(stderr, RESET);
	pcap_close(handle);
	return(EXIT_SUCCESS);
}