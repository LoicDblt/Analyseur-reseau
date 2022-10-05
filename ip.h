#include <string.h>
#include <netinet/ip.h>
#include <pcap.h>

#include "utile.h"

// Fonction d'affichage des adresses IP
void gestionIP(const u_char* paquet, int size_ethernet);