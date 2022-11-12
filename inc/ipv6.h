#ifndef IPV6_H
#define IPV6_H

/************** INCLUDES **************/

#include <netinet/ip6.h>

#include "ipv4.h"

/************* FONCTIONS **************/

// Fonction de gestion du protocole IPv6
void gestionIPv6(const u_char* paquet, const int offset);

#endif