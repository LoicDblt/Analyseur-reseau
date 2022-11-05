#ifndef IP_H 
#define IP_H

/************** INCLUDES **************/

#include <netinet/ip.h>

#include "tcp.h"
#include "udp.h"
#include "utile.h"

/************* CONSTANTES *************/

#define TCP	6
#define UDP	17

/************* FONCTIONS **************/

// Fonction de gestion du protocole IP
void gestionIP(const u_char* paquet, const int offset);

#endif