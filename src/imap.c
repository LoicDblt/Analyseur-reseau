#include "../inc/imap.h"

void gestionIMAP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurIMAP = (u_int8_t*) paquet + offset;

	titreProto("IMAP", ROUGE);

	// Affiche le contenu complet du header IMAP
	if (niveauVerbo > SYNTHETIQUE){
		for (int i = 0; i < tailleHeader; i++)
			caraCtrl(*pointeurIMAP++);
	}

	// Affiche uniquement le tag et la commande (ou l'accusé)
	else{
		for (int i = 0; i < tailleHeader; i++){
			// N'affiche pas toutes les options de CAPABILITY
			if (memcmp(pointeurIMAP, CAPAB, sizeofSansSenti(CAPAB)) == 0){
				printf("%s\\r\\n", CAPAB);
				break;
			}
			else
				caraCtrl(*pointeurIMAP++);
		}
	}
}