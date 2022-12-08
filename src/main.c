#include "../inc/main.h"
int niveauVerbo = VERBOSITE_DEFAUT;

int main(int argc, char *argv[]){
	pcap_t* handle;					// Session handle
	char* device = "";				// The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string
	struct bpf_program fp;			// The compiled filter
	char* filter_exp = "";			// The filter expression
	bpf_u_int32 mask;				// Our netmask
	bpf_u_int32 net = 0;			// Our IP

	// Signifie qu'il y a des commutateurs
	if (argc > 1){
		// Force l'affichage du titre encadré
		niveauVerbo = 3;

		titreTrame("Enabled options");
		printf("\n\n");

		// Remets la verbosité sur le niveau par défaut
		niveauVerbo = VERBOSITE_DEFAUT;
	}

	// Gestion des commutateurs
	int opt;
	long int nbrPaquets = NBR_PAQUET_INF_1;
	char* nomFichier = "";

	// Récupère les valeurs des commutateurs
	while ((opt = getopt(argc, argv, "i:o:f:v:p:")) != -1){
		printf(VERT);
		fprintf(stderr, ROUGE);

		switch (opt){
			/* Interface */
			case 'i':
				if (optarg[0] == '-'){
					fprintf(stderr, "[Error] Specify the interface "
						"(-i)%s\n", RESET);
					return EXIT_FAILURE;
				}
				device = optarg;
				printf("[-i] Interface: %s\n", device);
				break;

			/* Trace hors-connexion */
			case 'o':
				nomFichier = optarg;
				if (access(nomFichier, F_OK) < 0){
					fprintf(stderr, "[Error] File not found (%s)%s\n",
						nomFichier, RESET);
					return EXIT_FAILURE;
				}
				handle = pcap_open_offline(nomFichier, errbuf);
				printf("[-o] Offline file: %s\n", nomFichier);
				break;

			/* Filtrage */
			case 'f':
				printf("[-f] Filter: %s\n", optarg);
				filter_exp = optarg;
				break;

			/* Verbosité */
			case 'v':
				niveauVerbo = atoi(optarg);
				char* verbosite;
				switch (niveauVerbo){
					case CONCIS:
						verbosite = "concise";
						break;

					case SYNTHETIQUE:
						verbosite = "synthetic";
						break;

					case COMPLET:
						verbosite = "complete";
						break;

					default:
						fprintf(stderr, "[Error] Unknow level of verbosity "
							"(1 (very concise) to 3 (complete))%s\n",
							RESET);
						return EXIT_FAILURE;
				}
				printf("[-v] Level of verbosity: %s (%s)\n", optarg,
					verbosite);
				break;

			/* Nombre de paquets à afficher */
			case 'p':
				nbrPaquets = atoi(optarg);
				if (nbrPaquets < NBR_PAQUET_INF_1){
					fprintf(stderr, "[Error] Number of packets to compute "
						"must be over %d%s\n", NBR_PAQUET_INF_1, RESET);
					return EXIT_FAILURE;
				}
				printf("[-p] Number of packets to compute: %ld",
					nbrPaquets);

				// Préviens si vaut "-1" ou "0" que c'est infini
				if (
					nbrPaquets == NBR_PAQUET_INF_1 ||
					nbrPaquets == NBR_PAQUET_INF_0
				)
					printf(" (unlimited)");

				printf("\n");
				break;

			/* Inconnu */
			default:
				fprintf(stderr, "[Error] Unknow option \"-%c\" %s\n",
					optopt, RESET);
				return EXIT_FAILURE;
		}
		printf(RESET);
	}
	fprintf(stderr, "\n%s", ROUGE);

	// Si on n'est pas en mode hors-connexion
	if (strlen(nomFichier) == 0){
		// Défini l'interface si elle ne l'a pas été avec un flag
		if (device == NULL || device[0] == '\0'){
			pcap_if_t *interfaces;

			if (pcap_findalldevs(&interfaces,errbuf) == -1) {
				fprintf(stderr, "[Error] Error while retrieving devices: %s\n",
					errbuf);
				return EXIT_FAILURE;
			}
			device = interfaces->name;
		}

		if (device == NULL){
			fprintf(stderr, "[Error] Couldn't find default device: %s\n",
				errbuf);
			return EXIT_FAILURE;
		}

		// Cherche les propriétés de l'interface
		if (pcap_lookupnet(device, &net, &mask, errbuf) < 0){
			fprintf(stderr, "[Error] Couldn't get netmask for device %s "
				":\n\t=> %s\n\n", device, errbuf);
			mask = 0;
		}

		// Ouvre la session en mode "promiscuous"
		handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL){
			fprintf(stderr, "[Error] Couldn't open device %s:\n\t=> %s%s\n",
				device, errbuf, RESET);
			return EXIT_FAILURE;
		}
	}

	// Si on a précisé une trace hors-connexion et une interface
	else if (strlen(nomFichier) > 0 && !(device == NULL || device[0] == '\0')){
		fprintf(stderr, "[Caution] Interface %s will be overridden by the "
			"offline trace (%s)\n\n", device, nomFichier);
	}

	// Compile et applique le filtre
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "[Error] Couldn't parse filter \"%s\":\n\t=> %s%s\n",
			filter_exp, pcap_geterr(handle), RESET);
		return EXIT_FAILURE;
	}
	if (pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "[Error] Couldn't install filter %s:\n\t=> %s%s\n",
			filter_exp, pcap_geterr(handle), RESET);
		return EXIT_FAILURE;
	}

	// Récupère "nbrPaquets" paquets (-1 = sans limite)
	if (pcap_loop(handle, nbrPaquets, gestionEthernet, NULL) < 0){
		fprintf(stderr, "[Error] Error while reading the package %s%s\n",
			device, RESET);
		return EXIT_FAILURE;
	}

	// Ferme la session
	fprintf(stderr, RESET);
	pcap_close(handle);

	// Pour la finition !
	if (niveauVerbo == CONCIS)
		printf("\n");

	return EXIT_SUCCESS;
}