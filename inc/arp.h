#ifndef ARP_H 
#define ARP_H

#include <net/if_arp.h>
#include <pcap.h>

#include "ethernet.h"
#include "utile.h"

// Fonction de gestion du protocole ARP
void gestionARP(const u_char* paquet, const int size_ethernet);

#endif