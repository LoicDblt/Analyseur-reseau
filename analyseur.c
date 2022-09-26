#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // Fix pour macOS (pcap_lookupdev deprecated)

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>

// Flag IO : 0 = src / 1 = dest
void affichageMac(const struct ether_header *ethernet, int FlagIO){
	int i;
	unsigned addr;
	if (FlagIO == 0)
		printf("\033[35mMAC src : ");
	else if (FlagIO == 1)
		printf("\033[35mMAC dest : ");
	else{
		fprintf(stderr, "Mauvaise valeur flag IO\n");
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

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
	static int compteurPaquets = 1;
	if (compteurPaquets == 1)
		printf("\n\t#### %dère Trame ####", compteurPaquets);
	else if (compteurPaquets == 2)
		printf("\n\t#### %dnd Trame ####", compteurPaquets);
	else
		printf("\n\t#### %dème Trame ####", compteurPaquets);
	const struct ether_header *ethernet;
	const struct ip *ip;
	int size_ethernet = sizeof(struct ether_header);
	ethernet = (struct ether_header*)(packet);
	ip = (struct ip*)(packet + size_ethernet);

	printf("\n*** Informations MAC ***\n");
	affichageMac(ethernet, 0); // src
	affichageMac(ethernet, 1); // dest
	printf("EtherType : %.2x\033[00m", ntohs(ethernet->ether_type)); // EtherType

	printf("\n\n*** Informations IP ***\n");
	printf("\033[33mIP src : %s\n", inet_ntoa(ip->ip_src)); // src
	printf("IP dest : %s\033[00m\n", inet_ntoa(ip->ip_dst)); // dest
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