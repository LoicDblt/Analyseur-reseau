#include <netinet/tcp.h>
#include <pcap.h>

#include "utile.h"

// Fonction de gestion du protocole TCP
void gestionTCP(const u_char* paquet, int size_ip);