#ifndef IMAP_H
#define IMAP_H

/*************** INCLUDE **************/

#include "utile.h"

/************* CONSTANTE **************/

#define CAPAB	"CAPABILITY"

/************** FONCTION **************/

// Fonction de gestion du protocole IMAP
void gestionIMAP(const u_char* paquet, const int offset, int tailleHeader);

#endif