#ifndef POP_H
#define POP_H

/************** INCLUDES **************/

#include "utile.h"

/************* CONSTANTES *************/

#define AUTH	"AUTH"
#define CAPA	"CAPA"
#define DELE	"DELE"
#define ERR		"-ERR"
#define LAST	"LAST"
#define LIST	"LIST"
#define NOOP	"NOOP"
#define OK		"+OK"
#define PASS	"PASS"
#define QUIT	"QUIT"
#define RETR	"RETR"
#define RSET	"RSET"
#define TOP		"TOP"
#define UIDL	"UIDL"
#define USER	"USER"
#define STAT	"STAT"

/************* FONCTIONS **************/

// Fonction de gestion du protocole POP
void gestionPOP(const u_char* paquet, const int offset, int tailleHeader);

#endif