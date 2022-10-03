#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "utile.h"
#include <pcap.h>

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* paquet);