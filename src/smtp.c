#include "../inc/smtp.h"

void gestionSMTP(const u_char* paquet, const int offset){
	// On se place après l'entête TCP
	u_int8_t* pointeurSMTP =  (u_int8_t*) paquet + offset;

	char lettre = *pointeurSMTP++;

	// Vérifie que le contenu SMTP commence par un code (2xx à 5xx)
	if (lettre != '2' && lettre != '3' && lettre != '4' && lettre != '5')
		return;

	titreViolet("SMTP");

	// Affiche le contenu SMTP
	int i = 0;
	while (i != 2){
		printf("%c", lettre);

		// Vérifie si on a le cas "\r\n"
		if (lettre == '\r')
			i = 1;
		else if (i == 1){
			if (lettre == '\n')
				break;
			else
				i = 0;
		}

		lettre = *pointeurSMTP++;
	}
}