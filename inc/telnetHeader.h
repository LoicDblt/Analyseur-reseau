#ifndef TELNETHEADER_H
#define TELNETHEADER_H

/************** INCLUDES **************/

#include "telnet.h"
#include "utile.h"

/************* CONSTANTES *************/

#define COMMANDE	0xff

/************* FONCTIONS **************/

// Fonction de gestion du protocole Telnet
void gestionTelnet(const u_char* paquet, const int offset, int tailleHeader);

#endif