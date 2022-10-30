#ifndef DNS_H 
#define DNS_H

/************** INCLUDES **************/

#include "bootpHeader.h"
#include "utile.h"

/************* CONSTANTES *************/

// Classes
#define IN	1
#define CS	2
#define CH	3
#define HS	4

// Types
#define A		1	// A host address
#define NS		2	// An authoritative name server
#define CNAME	5	// The canonical name for an alias
#define SOA		6	// Marks the start of a zone of authority
#define WKS	 	11	// A well known service description
#define PTR		12	// A domain name pointer
#define HINFO	13	// Host information
#define MINFO	14	// Mailbox or mail list information
#define MX		15	// Mail exchange
#define TXT		16	// Text strings

// Affichage ASCII nom de domaine
#define FIN		0x00
#define POINT1	0x03
#define POINT2	0x08

// Autre
#define AFFICHEA		0xc00c
#define AFFICHECNAME	0xc02f
#define TAILLEMAX		254		// Taille maximale d'un nom de domaine

/************* FONCTIONS **************/

// Fonction de vérification du retour de snprintf
void verifTaille(const int retourTaille, const size_t element);

// Fonction de conversion et d'affichage de la durée (heures, minutes, secondes)
void affichageDuree(const unsigned int dureeSecondes);

// Fonction d'affichage du type de requête depuis un pointeur
void affichageType(const unsigned int type);

// Fonction d'affichage de la classe de requête depuis un pointeur
void affichageClasse(const unsigned int classe);

// Fonction de gestion du protocole DNS
void gestionDNS(const u_char* paquet, const int size_udp);

#endif