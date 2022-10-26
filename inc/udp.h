#include <netinet/udp.h>
#include <pcap.h>

#include "utile.h"
#include "bootpHeader.h"

void gestionUDP(const u_char* paquet, int size_ip);