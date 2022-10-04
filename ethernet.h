#include <string.h>
#include <net/ethernet.h>
#include <pcap.h>

#include "utile.h"
#include "ip.h"

// Fonction d'affichage des adresses MAC
// int flagIO : 0 = src / 1 = dest
void affichageMac(const struct ether_header *ethernet, int FlagIO);

// Fonction de callback pour pcap_loop (=> main.c)
void gestionEthernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* paquet);