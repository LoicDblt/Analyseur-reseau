#ifndef IP_H
#define IP_H

/************** INCLUDES **************/

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "tcp.h"
#include "udp.h"
#include "utile.h"

/************* CONSTANTES *************/

#define TCP		0x06
#define UDP		0x11

#define MASQUE 0xffffff

/************* FONCTIONS **************/

// Fonction de gestion du protocole IP
void gestionIP(const u_char* paquet, const int offset, int type);

#endif