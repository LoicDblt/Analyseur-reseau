#ifndef FTP_H
#define FTP_H

/************** INCLUDE ***************/

#include "utile.h"

/************** FONCTION **************/

// Fonction de gestion du protocole FTP
void gestionFTP(const u_char* paquet, const int offset, int tailleHeader);

#endif