#include <netinet/ip.h>
#include <pcap.h>

#include "tcp.h"
#include "udp.h"
#include "utile.h"

#define TCP 6
#define UDP 17

// Fonction de gestion du protocole IP
void gestionIP(const u_char* paquet, const int size_ethernet);