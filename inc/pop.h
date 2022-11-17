#ifndef POP_H
#define POP_H

/************** INCLUDES **************/

#include "utile.h"

/************* CONSTANTES *************/

#define USER	"USER"
#define PASS	"PASS"
#define STAT	"STAT"
#define LIST	"LIST"
#define UIDL	"UIDL"
#define RETR	"RETR"
#define DELE	"DELE"
#define TOP		"TOP"
#define LAST	"LAST"
#define RSET	"RSET"
#define NOOP	"NOOP"
#define QUIT	"QUIT"
#define OK		"+OK"

/************* FONCTIONS **************/

// Fonction de gestion du protocole POP
void gestionPOP(const u_char* paquet, const int offset, int tailleHeader);

#endif