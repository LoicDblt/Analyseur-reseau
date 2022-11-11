#ifndef TCP_H
#define TCP_H

/************** INCLUDES **************/

#include <netinet/tcp.h>

#include "http.h"
#include "smtp.h"
#include "utile.h"

/************* CONSTANTES *************/

#define PORT_SMTP_1		25
#define PORT_SMTP_2		587
#define PORT_SMTP_TLS	465
#define PORT_HTTP		80

/************* FONCTIONS **************/

// Fonction de gestion du protocole TCP
void gestionTCP(const u_char* paquet, const int offset, int tailleTotale);

#endif