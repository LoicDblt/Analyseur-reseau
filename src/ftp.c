#include "../inc/ftp.h"

void gestionFTP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurFTP = (u_int8_t*) paquet + offset;

	titreProto("FTP", ROUGE);

	if (niveauVerbo > SYNTHETIQUE){
		// N'affiche pas le "\r\n" à la fin (d'où le "- 2")
		for (int i = 0; i < tailleHeader - 2; i++)
			printf("%c", *pointeurFTP++);
	}
	else{
		for (int i = 0; i < tailleHeader - 2; i++){
			if (*pointeurFTP == ' ')
				break;

			printf("%c", *pointeurFTP++);
		}
	}
}