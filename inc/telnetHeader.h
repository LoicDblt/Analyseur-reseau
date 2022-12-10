#ifndef TELNETHEADER_H
#define TELNETHEADER_H

/************** INCLUDES **************/

#include "telnet.h" // Header non inclus par défaut sur MacOS
#include "utile.h"

/************** FONCTION **************/

// Fonction de gestion du protocole Telnet
void gestionTelnet(const u_char* paquet, const int offset, int tailleHeader);

#endif