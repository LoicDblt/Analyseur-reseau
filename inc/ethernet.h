#ifndef ETHERNET_H
#define ETHERNET_H

/************** INCLUDES **************/

#if __APPLE__
	#include <net/ethernet.h>
#else
	#include <netinet/ether.h>
#endif

#include <time.h>

#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "utile.h"

/************* CONSTANTES *************/

#define MAX_BUFF_TRAME		48 // Bien assez grand dans tous les cas
#define TAILLE_TIMESTAMP	48

/************* FONCTIONS **************/

// Fonction d'affichage du type ethernet
void affichageEtherType(uint16_t type);

// Fonction de gestion du protocole Ethernet
void gestionEthernet(u_char* args, const struct pcap_pkthdr* pkthdr,
	const u_char* paquet);

#endif