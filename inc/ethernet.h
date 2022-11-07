#ifndef ETHERNET_H
#define ETHERNET_H

/************** INCLUDES **************/

#include <net/ethernet.h>

#include "arp.h"
#include "ip.h"
#include "utile.h"

/************* CONSTANTES *************/

#define TAILLE_TIMESTAMP	48

/************* FONCTIONS **************/

// Fonction d'affichage du type ethernet
void affichageEtherType(uint16_t type);

// Fonction de gestion du protocole Ethernet
void gestionEthernet(u_char *args, const struct pcap_pkthdr* pkthdr,
	const u_char* paquet);

#endif