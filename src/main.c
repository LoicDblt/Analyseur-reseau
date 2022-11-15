// Masque le warning "pcap_lookupdev deprecated"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "../inc/main.h"
int niveauVerbo = 1;

int main(int argc, char *argv[]){
	pcap_t* handle;					// Session handle
	char* device = "";				// The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string
	struct bpf_program fp;			// The compiled filter
	char* filter_exp = "";			// The filter expression
	bpf_u_int32 mask;				// Our netmask
	bpf_u_int32 net = 0;			// Our IP

	// Gestion des commutateurs
	int iFlag = 0, oFlag = 0, fFlag = 0, vFlag = 0, pFlag = 0;
	int opt;
	int nbrPaquets = -1;
	char* nomFichier;

	while ((opt = getopt (argc, argv, "i:o:f:v:p:")) != -1){
		if (iFlag == 0 && oFlag == 0 && fFlag == 0 && vFlag == 0 && pFlag == 0)
			titreTrame("Enabled options", -1);

		printf(VERT);

		switch (opt){
			/* Interface */
			case 'i':
				iFlag = 1;
				if (optarg[0] == '-'){
					fprintf(stderr, "%s|Error| Specify the interface "
						"(-i)%s\n", ROUGE, RESET);
					return EXIT_FAILURE;
				}
				device = optarg;
				printf("[-i] Interface : %s\n", device);
				break;

			/* Fichier offline */
			case 'o':
				oFlag = 1;
				nomFichier = optarg;
				if (access(nomFichier, F_OK) < 0){
					fprintf(stderr, "%s|Error| File not found%s\n",
						ROUGE, RESET);
					return EXIT_FAILURE;
				}
				handle = pcap_open_offline(nomFichier, errbuf);
				printf("[-o] Offline file : %s\n", nomFichier);
				break;

			/* Filtrage */
			case 'f':
				fFlag = 1;
				printf("[-f] Filter : %s\n", optarg);
				filter_exp = optarg;
				break;

			/* Verbosité */
			case 'v':
				vFlag = 1;
				niveauVerbo = atoi(optarg);
				char* verbosite;
				switch (niveauVerbo){
					case CONCIS:
						verbosite = "very concise";
						break;

					case SYNTHETIQUE:
						verbosite = "synthetic";
						break;

					case COMPLET:
						verbosite = "complete";
						break;

					default:
						fprintf(stderr, "%s|Error| Unknow level of verbosity "
							"(1 [very concise] to 3 [complete])%s\n",
							ROUGE, RESET);
						return EXIT_FAILURE;
				}
				printf("[-v] Level of verbosity : %s [%s]\n", optarg, verbosite);
				break;

			/* Nombre de paquets à afficher */
			case 'p': 
				pFlag = 1;
				nbrPaquets = atoi(optarg);
				if (nbrPaquets < -1){
					fprintf(stderr, "%s|Error| Number of packets to compute "
						"must be over -1%s\n", ROUGE, RESET);
					return EXIT_FAILURE;
				}
				printf("[-p] Number of packets to compute : %d\n", nbrPaquets);
				break;

			/* Inconnu */
			default:
				fprintf(stderr, "%s|Error| Unknow option \"-%c\" %s\n",
					ROUGE, optopt, RESET);
				return EXIT_FAILURE;
		}
		printf(RESET);
	}
	fprintf(stderr, "%s\n", ROUGE);

	// Si on est pas en mode offline
	if (oFlag == 0){
		// Défini l'interface si elle ne l'a pas été avec un flag
		if (device == NULL || device[0] == '\0')
			device = pcap_lookupdev(errbuf);
		if (device == NULL){
			fprintf(stderr, "|Error| Couldn't find default device : %s\n",
				errbuf);
			return EXIT_FAILURE;
		}

		// Cherche les propriétés de l'interface
		if (pcap_lookupnet(device, &net, &mask, errbuf) < 0){
			fprintf(stderr, "|Error| Couldn't get netmask for device %s "
				":\n%s\n", device, errbuf);
			mask = 0;
		}

		// Ouvre la session en mode "promiscuous"
		handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL){
			fprintf(stderr, "|Error| Couldn't open device %s :\n%s\n",
				device, errbuf);
			return EXIT_FAILURE;
		}
	}

	// Compile et applique le filtre
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "|Error| Couldn't parse filter %s :\n%s\n",
			filter_exp, pcap_geterr(handle));
		return EXIT_FAILURE;
	}
	if (pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "|Error| Couldn't install filter %s :\n%s\n",
			filter_exp, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	// Récupère des paquets
	if (pcap_loop(handle, nbrPaquets, gestionEthernet, NULL) < 0){
		fprintf(stderr, "|Error| Error while reading the package %s\n",
			device);
		return EXIT_FAILURE;
	}

	// Ferme la session
	fprintf(stderr, RESET);
	pcap_close(handle);
	return EXIT_SUCCESS;
}