#ifndef TCP_H 
#define TCP_H

/************** INCLUDES **************/

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "utile.h"

/************* FONCTIONS **************/

// Fonction de gestion du protocole TCP
void gestionTCP(const u_char* paquet, const int size_ip);

#endif