#include <netinet/tcp.h>
#include <pcap.h>

#include "utile.h"

void gestionTCP(const u_char* paquet, int size_ip);