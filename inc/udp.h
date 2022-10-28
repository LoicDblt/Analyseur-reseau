#ifndef UDP_H 
#define UDP_H

#include <netinet/udp.h>
#include <pcap.h>

#include "bootpHeader.h"
#include "utile.h"

// Fonction de gestion du protocole UDP
void gestionUDP(const u_char* paquet, const int size_ip);

#endif