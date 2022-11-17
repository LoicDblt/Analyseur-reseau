#include "../inc/smtp.h"

void gestionSMTP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurSMTP = (u_int8_t*) paquet + offset;

	titreProto("SMTP", ROUGE);

	if (niveauVerbo > SYNTHETIQUE){
		// Affichage du contenu complet du header SMTP
		for (int i = 0; i < tailleHeader; i++)
			printf("%c", *pointeurSMTP++);
	}

	else{
		// Récupère uniquement le code dans le header SMTP
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