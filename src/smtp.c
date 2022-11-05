#include "../inc/smtp.h"

void gestionSMTP(const u_char* paquet, const int offset){
	// On se place après l'entête TCP
	u_int8_t* pointeurSMTP =  (u_int8_t*) paquet + offset;

	char lettre = *pointeurSMTP++;
	int i = 0;

	// Vérifie que le contenu SMTP commence par un code (2xx à 5xx)
	if (lettre != '2' && lettre != '3' && lettre != '4' && lettre != '5'){
		return;
	}
	titreViolet("SMTP");

	// Affiche le contenu SMTP
	while (i != 2){
		printf("%c", lettre);

		if (lettre == '\r')
			i++;
		if (lettre == '\n' && i == 1)
			break;

		lettre = *pointeurSMTP++;
	}
}