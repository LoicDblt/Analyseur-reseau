#ifndef FTP_H
#define FTP_H

/************** INCLUDES **************/

#include "utile.h"

/************* FONCTIONS **************/

// Fonction de gestion du protocole FTP
void gestionFTP(const u_char* paquet, const int offset, int tailleHeader);

#endif