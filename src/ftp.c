#include "../inc/ftp.h"

void gestionFTP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurFTP = (u_int8_t*) paquet + offset;

	titreProto("FTP", ROUGE);

	// Affiche le contenu complet du header FTP
	if (niveauVerbo > SYNTHETIQUE){
		for (int i = 0; i < tailleHeader; i++)
			caraCtrl(*pointeurFTP++);
	}

	// Affiche uniquement le code ou la commande
	else{
		for (int i = 0; i < tailleHeader; i++){
			if (*pointeurFTP == ' ')
				break;

			caraCtrl(*pointeurFTP++);
		}
	}
}