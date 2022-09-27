#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // Fix pour macOS (pcap_lookupdev deprecated)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>

void titreViolet(char* message){
	printf("\033[35m*** %s ***\033[00m\n", message);
}
void titreCian(char* message, int compteur){
	if (compteur == -1)
		printf("\n\t\033[36m#### %s ####\033[00m\n", message);
	else
		printf("\n\t\033[36m#### %d%s ####\033[00m\n", compteur, message);
}

// Flag IO : 0 = src / 1 = dest
void affichageMac(const struct ether_header *ethernet, int FlagIO){
	int i;
	unsigned addr;
	printf("\033[33m");
	if (FlagIO == 0)
		printf("MAC src : ");
	else if (FlagIO == 1)
		printf("MAC dest : ");
	else{
		printf("\033[00m");
		fprintf(stderr, "Mauvaise valeur du flag IO\n");
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
	printf("\033[00m\n");
}

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
	static int compteurPaquets = 1;
	if (compteurPaquets == 1)
		titreCian("ère trame", compteurPaquets);
	else
		titreCian("ème trame", compteurPaquets);
	const struct ether_header *ethernet;
	const struct ip *ip;
	int size_ethernet = sizeof(struct ether_header);
	ethernet = (struct ether_header*)(packet);
	ip = (struct ip*)(packet + size_ethernet);

	titreViolet("Informations MAC");
	affichageMac(ethernet, 0); // src
	affichageMac(ethernet, 1); // dest
	printf("\033[33m");
	printf("EtherType : %.2x", ntohs(ethernet->ether_type)); // EtherType
	printf("\033[00m\n\n");

	titreViolet("Informations IP");
	printf("\033[33m");
	printf("IP src : %s\n", inet_ntoa(ip->ip_src)); // src
	printf("IP dest : %s\n", inet_ntoa(ip->ip_dst)); // dest
	printf("\033[00m");
	compteurPaquets++;
}

int main(int argc, char *argv[]){
	pcap_t *handle;					/* Session handle */
	char *dev;						/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */

	int iFlag = 0, oFlag = 0, fFlag = 0, vFlag = 0;
	int opt, niveau;
	char* nomFichier;
	while ((opt = getopt (argc, argv, "i:o:f:v:")) != -1){
		if (iFlag == 0 && oFlag == 0 && fFlag == 0 && vFlag == 0)
			titreCian("Options activées", -1);
		printf("\033[32m");

		switch (opt){
			case 'i':
				iFlag = 1;
				printf("Flag i : %s\n", optarg);
				break;
			case 'o':
				oFlag = 1;
				printf("Flag o : %s\n", optarg);
				nomFichier = optarg;
				if (access(nomFichier, F_OK) < 0){
					fprintf(stderr, "\033[31mFichier introuvable\033[00m\n");
					return EXIT_FAILURE;
				}
				break;
			case 'f':
				fFlag = 1;
				printf("Flag f : %s\n", optarg);
				break;
			case 'v':
				vFlag = 1;
				printf("Flag v : %s\n", optarg);
				niveau = atoi(optarg);
				if (niveau < 1 || niveau > 3){
					fprintf(stderr, "\033[31mNiveau de verbosité inconnu (1 [synthétique] à 3 [complet])\033[00m\n");
					return EXIT_FAILURE;
				}
				break;
			case '?':
				fprintf(stderr, "\033[31mOption \"-%c\" inconnue !\033[00m\n", optopt);
				return EXIT_FAILURE;
			default:
				return EXIT_FAILURE;
		}
		printf("\033[00m");
	}

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL){
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) < 0){
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	/* Compile and apply the filter */
	// if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	// 	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	// 	return(2);
	// }
	// if (pcap_setfilter(handle, &fp) == -1) {
	// 	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	// 	return(2);
	// }

	/* Grab some packets */
	if (pcap_loop(handle, 2, my_callback, NULL) < 0){
		fprintf(stderr, "Error reading packet %s\n", dev);
		return(2);
	}

	/* And close the session */
	pcap_close(handle);
	return(0);
}