#ifndef TCP_H
#define TCP_H

/************** INCLUDES **************/

#include <netinet/tcp.h>

#include "ftp.h"
#include "http.h"
#include "imap.h"
#include "pop.h"
#include "smtp.h"
#include "utile.h"

/************* CONSTANTES *************/

#define PORT_FTP		21
#define PORT_HTTP		80
#define PORT_IMAP		143
#define PORT_POP		110
#define PORT_SMTP_1		25
#define PORT_SMTP_2		587

/************* FONCTIONS **************/

// Fonction de gestion du protocole TCP
void gestionTCP(const u_char* paquet, const int offset, int tailleTotale);

#endif