#ifndef BOOTPHEADER_H 
#define BOOTPHEADER_H

/************** INCLUDES **************/

#include <pcap.h>

#include "bootp.h"
#include "utile.h"

/************* CONSTANTES *************/

#define ETHERNET	0x01
#define BROADCAST	0x8000
#define UNICAST		0x0000

/************* FONCTIONS **************/

// Fonction d'affichage des strings depuis un pointeur
void affichageString(const u_int8_t* pointeur, const  u_int8_t longueur);

// Fonction d'affichage des durées depuis un pointeur
void affichageDuree(const u_int8_t* pointeur);

// Fonction de gestion du protocole BootP
void gestionBootP(const u_char* paquet, const int offset);

#endif