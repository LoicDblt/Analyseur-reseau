#ifndef UDP_H
#define UDP_H

/************** INCLUDES **************/

#include <netinet/udp.h>

#include "bootpHeader.h"
#include "dns.h"
#include "utile.h"

/************** CONSTANTE *************/

#define PORT_DNS	53

/************** FONCTION **************/

// Fonction de gestion du protocole UDP
void gestionUDP(const u_char* paquet, const int offset);

#endif