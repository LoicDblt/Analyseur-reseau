#ifndef IMAP_H
#define IMAP_H

/************** INCLUDES **************/

#include "utile.h"

/************* CONSTANTES *************/

#define CAPAB	"CAPABILITY"

/************* FONCTIONS **************/

// Fonction de gestion du protocole IMAP
void gestionIMAP(const u_char* paquet, const int offset, int tailleHeader);

#endif