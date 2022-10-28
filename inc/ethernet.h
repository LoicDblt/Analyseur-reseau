#include <net/ethernet.h>
#include <pcap.h>
#include <string.h>

#include "arp.h"
#include "ip.h"
#include "utile.h"

// Fonction de gestion du protocole Ethernet
void gestionEthernet(u_char *args, const struct pcap_pkthdr* pkthdr,
const u_char* paquet);