#include "../inc/smtp.h"

void gestionSMTP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurSMTP =  (u_int8_t*) paquet + offset;

	titreViolet("SMTP");

	// Affichage du contenu du header SMTP
	for (int i = 0; i < tailleHeader; i++)
		printf("%c", *pointeurSMTP++);
}