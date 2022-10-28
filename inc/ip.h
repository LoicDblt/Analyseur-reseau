#include <netinet/ip.h>
#include <pcap.h>

#include "utile.h"

// Fonction de gestion du protocole IP
void gestionIP(const u_char* paquet, int size_ethernet);