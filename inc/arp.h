#ifndef ARP_H
#define ARP_H

/************** INCLUDES **************/

#include <net/if_arp.h>

#include "ethernet.h"
#include "utile.h"

/************* FONCTIONS **************/

// Fonction de gestion du protocole ARP
void gestionARP(const u_char* paquet, const int offset);

#endif