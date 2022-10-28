#include <pcap.h>

#include "bootp.h"
#include "utile.h"

#define BROADCAST	0x8000
#define UNICAST		0x0000

// Fonction d'affichage d'IP depuis un pointeur
void affichageIP(u_int8_t* pointeur, u_int8_t longueur);

// Fonction d'affichage des strings depuis un pointeur
void affichageString(u_int8_t* pointeur, u_int8_t longueur);

// Fonction de gestion du protocole BootP
void gestionBootP(const u_char* paquet, int size_udp);