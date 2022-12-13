#ifndef UTILE_H
#define UTILE_H

/************** INCLUDES **************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "main.h"

/************* CONSTANTES *************/

// Couleurs pour l'affichage
#define ROUGE		"\033[31m"
#define VERT		"\033[32m"
#define JAUNE		"\033[33m"
#define BLEU		"\033[34m"
#define MAGENTA 	"\033[35m"
#define CYAN		"\033[36m"
#define RESET		"\033[00m"
#define VIDER_LIGNE	"\033[A\033[2K"

// Codes ASCII pour les noms de domaine
#define CODE_ASCII		0xc0
#define CODE_CONTROLE	0x20
#define FIN				0x00

// Niveaux de verbosité
#define CONCIS		1
#define SYNTHETIQUE	2
#define COMPLET		3

/************* FONCTIONS **************/

// Renvoie la taille sans la valeur sentinnelle
#define sizeofSansSenti(taille) sizeof(taille) - 1

// Titre des trames
void titreTrame(const char* message);

// Titre des protocoles
void titreProto(const char* message, char* couleur);

// Passe à la ligne suivante si verbosité "complet"
void sautLigneOuSeparateur(void);

// Fonction de vérification du retour de snprintf
void verifTaille(const int retourTaille, const size_t tailleBuffer);

// Fonction d'affichage d'adresse MAC
void affichageAdresseMAC(const u_int8_t* pointeur);

// Fonction d'affichage d'adresse IPv4 depuis un pointeur
void affichageAdresseIPv4(const u_int8_t* pointeur, const u_int8_t longueur);

// Fonction d'affichage d'adresse IPv6 depuis un pointeur
void affichageAdresseIPv6(const u_int8_t* pointeur, const u_int8_t longueur);

// Fonction d'affichage de nom de domaine depuis un pointeur
unsigned int affichageNomDomaine(const u_int8_t* pointeur,
	const unsigned int longueur);

// Fonction de conversion et d'affichage de la durée (heures, minutes, secondes)
void affichageDureeConvertie(unsigned int dureeSecondes);

// Affiche les caractères de contrôle '\r' et '\n'
int caraCtrl(char caractere);

// Affiche les ports avec un message adapté au niveau de verbosité
void afficheSrcDstPorts(const unsigned portSrc, const unsigned portDst);

// Affiche les adresses IP avec un message adapté au niveau de verbosité
void afficheSrcDstAddrIP(const char* ipSrc, const char* ipDst);

#endif