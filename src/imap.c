#include "../inc/imap.h"

void gestionIMAP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurIMAP = (u_int8_t*) paquet + offset;

	titreProto("IMAP", ROUGE);

	// Affiche le contenu complet du header IMAP
	if (niveauVerbo > SYNTHETIQUE){
		// N'affiche pas le "\r\n" à la fin (d'où le "- 2")
		for (int i = 0; i < tailleHeader - 2; i++)
			printf("%c", *pointeurIMAP++);
	}

	// Affiche uniquement le tag et la commande (ou l'accusé)
	else{
		for (int i = 0; i < tailleHeader - 2; i++){
			// N'affiche pas toutes les options de CAPABILITY
			if (memcmp(pointeurIMAP, CAPAB, sizeofSansSenti(CAPAB)) == 0){
				printf("%s", CAPAB);
				break;
			}
			else
				printf("%c", *pointeurIMAP++);
		}
	}
}