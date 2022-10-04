#include <string.h>
#include <netinet/ip.h>
#include <pcap.h>

#include "utile.h"

// Fonction d'affichage des adresses IP
void affichageIP(const u_char* paquet, int size_ethernet);