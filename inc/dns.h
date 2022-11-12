#ifndef DNS_H
#define DNS_H

/************** INCLUDES **************/

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
#define AAAA	28	// A host address IPv6

// Op code
#define QUERY	0b0000
#define IQUERY	0b0001
#define STATUS	0b0010

// Z (Reserved)
#define ALLNULL	0b0000

// Reply code
#define NOERR	0	// No error
#define FORMERR	1	// Format error
#define FAILERR	2	// Server failure
#define NAMEERR	3	// Name error
#define NOTIMPL	4	// Not implemented
#define REFUSED	5	// Refused

// Type
#define REPONSE	1

// Autre
#define TAILLE_NOM_DOM	255
#define TAILLE_BIT		16
#define SEC_DANS_MIN	60
#define SEC_DANS_HEURE	3600
#define SEC_DANS_JOUR	86400

/************* FONCTIONS **************/

// Fonction de conversion et d'affichage de la durée (heures, minutes, secondes)
void affichageDureeConvertie(unsigned int dureeSecondes);

// Fonction d'affichage du type de requête depuis un pointeur
void affichageType(const unsigned int type);

// Fonction d'affichage de la classe de requête depuis un pointeur
void affichageClasse(const unsigned int classe);

// Fonction renvoyant 1 si le 'n' ième bit est placé
unsigned int recupereNiemeBit(const unsigned int nombre,
	const unsigned int nieme);

// Fonction d'affichage des bits du nombre
void affichageBinaire(const unsigned int nombre,
	const unsigned int nieme, const unsigned int nbrContigu);

// Fonction de gestion du protocole DNS
void gestionDNS(const u_char* paquet, const int offset);

#endif