#ifndef SMTP_H
#define SMTP_H

/*************** INCLUDE **************/

#include "utile.h"

/************** FONCTION **************/

// Fonction de gestion du protocole SMTP
void gestionSMTP(const u_char* paquet, const int offset, int tailleHeader);

#endif