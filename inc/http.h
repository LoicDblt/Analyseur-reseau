#ifndef HTTP_H
#define HTTP_H

/************** INCLUDE ***************/

#include "utile.h"

/************* CONSTANTES *************/

#define GET		"GET"
#define HEAD 	"HEAD"
#define POST	"POST"
#define PUT		"PUT"
#define DELETE	"DELETE"
#define CONNECT	"CONNECT"
#define OPTIONS	"OPTIONS"
#define TRACE	"TRACE"

#define DATA	"Data" // Juste pour de l'affichage, pas dans la RFC 7231

/************** FONCTION **************/

// Fonction de gestion du protocole HTTP
void gestionHTTP(const u_char* paquet, const int offset, int tailleHeader);

#endif