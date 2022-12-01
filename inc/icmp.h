#ifndef ICMP_H
#define ICMP_H

/************** INCLUDES **************/

#include <netinet/ip_icmp.h>

#include "utile.h"

/************* FONCTIONS **************/

// Fonction de gestion du protocole ICMP
void gestionICMP(const u_char* paquet, const int offset);

#endif