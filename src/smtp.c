#include "../inc/smtp.h"

void gestionSMTP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurSMTP = (u_int8_t*) paquet + offset;

	titreProto("SMTP", ROUGE);

	// Affiche le contenu complet du header SMTP
	if (niveauVerbo > SYNTHETIQUE){
		// N'affiche pas le "\r\n" à la fin (d'où le "- 2")
		for (int i = 0; i < tailleHeader - 2; i++)
			printf("%c", *pointeurSMTP++);
	}

	// Affiche uniquement le code dans le header SMTP
	else{
		for (int i = 0; i < tailleHeader; i++){
			if (
				*pointeurSMTP == ' ' ||
				*pointeurSMTP == '-' ||
				*pointeurSMTP == '\n'
			)
				break;

			printf("%c", *pointeurSMTP);
			pointeurSMTP++;
		}
	}
}