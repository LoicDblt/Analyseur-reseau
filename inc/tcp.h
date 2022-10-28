#ifndef TCP_H 
#define TCP_H

#include <netinet/tcp.h>
#include <pcap.h>

#include "utile.h"

// Fonction de gestion du protocole TCP
void gestionTCP(const u_char* paquet, const int size_ip);

#endif