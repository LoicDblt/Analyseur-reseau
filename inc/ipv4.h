#ifndef IPV4_H
#define IPV4_H

/************** INCLUDES **************/

#include <netinet/ip.h>

#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "utile.h"

/************* CONSTANTES *************/

#define ICMP	0x01
#define TCP		0x06
#define UDP		0x11

/************* FONCTIONS **************/

// Fonction de gestion du protocole IPv4
void gestionIPv4(const u_char* paquet, const int offset);

#endif