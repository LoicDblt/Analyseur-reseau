#ifndef UTILE_H
#define UTILE_H

/************** INCLUDES **************/

#include <arpa/inet.h>

#if __APPLE__
	#include <netinet/if_ether.h>
#else
	#include <netinet/ether.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/************* CONSTANTES *************/

// Couleurs pour l'affichage
#define ROUGE			"\033[31m"
#define VERT			"\033[32m"
#define JAUNE			"\033[33m"
#define BLEU			"\033[34m"
#define MAGENTA 		"\033[35m"
#define CYAN			"\033[36m"
#define RESET			"\033[00m"
#define VIDER_LIGNE		"\033[A\033[A"

/************* FONCTIONS **************/

// Titre de premier niveau
void titreCian(const char* message, const int compteur);

// Titre de second niveau
void titreViolet(const char* message);

// Fonction de vérification du retour de snprintf
void verifTaille(const int retourTaille, const size_t tailleBuffer);

// Fonction d'affichage des adresses MAC
void affichageAdresseMAC(const u_int8_t* pointeur);

// Fonction d'affichage d'IPv4 depuis un pointeur
void affichageAdresseIPv4(const u_int8_t* pointeur, const u_int8_t longueur);

// Fonction d'affichage d'IPv6 depuis un pointeur
void affichageAdresseIPv6(const u_int8_t* pointeur, const u_int8_t longueur);

#endif