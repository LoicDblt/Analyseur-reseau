#include <netinet/udp.h>
#include <pcap.h>

#include "utile.h"
#include "bootpHeader.h"

// Fonction de gestion du protocole UDP
void gestionUDP(const u_char* paquet, int size_ip);