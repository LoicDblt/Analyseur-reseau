#include <pcap.h>

#include "bootp.h"
#include "utile.h"

void gestionBootp(const u_char* paquet, int size_udp);