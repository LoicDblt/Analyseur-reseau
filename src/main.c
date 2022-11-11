// Masque le warning "pcap_lookupdev deprecated"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "../inc/main.h"

int main(int argc, char *argv[]){
	pcap_t* handle;					// Session handle
	char* device = "";				// The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string
	struct bpf_program fp;			// The compiled filter
	char* filter_exp = "";			// The filter expression
	bpf_u_int32 mask;				// Our netmask
	bpf_u_int32 net = 0;			// Our IP

	// Gestion des commutateurs
	int iFlag = 0, oFlag = 0, fFlag = 0, vFlag = 0;
	int opt, niveau;
	char* nomFichier;

	while ((opt = getopt (argc, argv, "i:o:f:v:")) != -1){
		if (iFlag == 0 && oFlag == 0 && fFlag == 0 && vFlag == 0)
			titreCian("Enabled options", -1);
		printf(VERT);

		switch (opt){
			case 'i': // Interface
				iFlag = 1;
				if (optarg[0] == '-'){
					fprintf(stderr, "%s|Error| Specify the interface "
						"(-i)%s\n", ROUGE, RESET);
					return EXIT_FAILURE;
				}
				device = optarg;
				printf("[-i] Interface : %s\n", optarg);
				break;

			case 'o': // Fichier offline
				oFlag = 1;
				printf("[-o] Offline file : %s\n", optarg);
				nomFichier = optarg;
				if (access(nomFichier, F_OK) < 0){
					fprintf(stderr, "%s|Error| File not found%s\n",
						ROUGE, RESET);
					return EXIT_FAILURE;
				}
				handle = pcap_open_offline(nomFichier, errbuf);
				break;

			case 'f': // Filtrage
				fFlag = 1;
				printf("[-f] Filter : %s\n", optarg);
				filter_exp = optarg;
				break;

			case 'v': // Verbosité
				vFlag = 1;
				niveau = atoi(optarg);
				char* verbosite;
				switch (niveau){
					case 1:
						verbosite = "very concise";
						break;

					case 2:
						verbosite = "synthetic";
						break;

					case 3:
						verbosite = "complete";
						break;

					default:
						fprintf(stderr, "%s|Error| Unknow level of verbosity "
							"(1 [very concise] to 3 [complete])%s\n",
							ROUGE, RESET);
						return EXIT_FAILURE;
				}
				printf("[-v] Level of verbosity %s [%s]\n", optarg, verbosite);
				break;

			case '?':
				fprintf(stderr, "%s|Error| Unknow option \"-%c\" %s\n",
					ROUGE, optopt, RESET);
				return EXIT_FAILURE;

			default:
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
	if (pcap_loop(handle, NBRPAQUETS, gestionEthernet, NULL) < 0){
		fprintf(stderr, "|Error| Error while reading the package %s\n",
			device);
		return EXIT_FAILURE;
	}

	// Ferme la session
	fprintf(stderr, RESET);
	pcap_close(handle);
	return EXIT_SUCCESS;
}