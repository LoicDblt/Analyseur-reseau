#ifndef SMTP_H
#define SMTP_H

/************** INCLUDES **************/

#include "utile.h"

/************* FONCTIONS **************/

// Fonction de gestion du protocole SMTP
void gestionSMTP(const u_char* paquet, const int offset);

#endif