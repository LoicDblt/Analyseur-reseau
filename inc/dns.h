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

// Affichage ASCII nom de domaine
#define FIN		0x00
#define POINT1	0x03
#define POINT2	0x08

// Autre
#define AFFICHEA		0xc00c
#define AFFICHECNAME	0xc02f
#define TAILLENOMDOM	255
#define TAILLEBIT		16

/************* FONCTIONS **************/

// Fonction de vérification du retour de snprintf
void verifTaille(const int retourTaille, const size_t tailleBuffer);

// Fonction de conversion et d'affichage de la durée (heures, minutes, secondes)
void affichageDureeConvertie(const unsigned int dureeSecondes);

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
void gestionDNS(const u_char* paquet, const int size_udp);

#endif