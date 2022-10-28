#ifndef BOOTPHEADER_H 
#define BOOTPHEADER_H

#include <pcap.h>

#include "bootp.h"

#include "ethernet.h"
#include "utile.h"

#define BROADCAST	0x8000
#define UNICAST		0x0000

// Fonction d'affichage d'IP depuis un pointeur
void affichageIP(const u_int8_t* pointeur, const u_int8_t longueur);

// Fonction d'affichage des strings depuis un pointeur
void affichageString(const u_int8_t* pointeur, const  u_int8_t longueur);

// Fonction d'affichage des durées depuis un pointeur
void affichageDurée(const char* message, const u_int8_t* pointeur);

// Fonction de gestion du protocole BootP
void gestionBootP(const u_char* paquet, const int size_udp);

#endif