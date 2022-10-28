#include <net/ethernet.h>
#include <pcap.h>
#include <string.h>

#include "utile.h"
#include "ip.h"

// Fonction de gestion du protocole Ethernet
void gestionEthernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* paquet);