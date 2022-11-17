#include "../inc/http.h"

void gestionHTTP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurHTTP = (u_int8_t*) paquet + offset;
	char* type = "";

	titreProto("HTTP", ROUGE);

	// Si on trouve une méthode d'HTTP (RFC 7231)
	if (memcmp(pointeurHTTP, GET, sizeofSansSenti(GET)) == 0)
		type = GET;
	else if	(memcmp(pointeurHTTP, HEAD, sizeofSansSenti(HEAD)) == 0)
		type = HEAD;
	else if (memcmp(pointeurHTTP, POST, sizeofSansSenti(POST)) == 0)
		type = POST;
	else if (memcmp(pointeurHTTP, PUT, sizeofSansSenti(PUT)) == 0)
		type = PUT;
	else if (memcmp(pointeurHTTP, DELETE, sizeofSansSenti(DELETE)) == 0)
		type = DELETE;
	else if (memcmp(pointeurHTTP, CONNECT, sizeofSansSenti(CONNECT)) == 0)
		type = CONNECT;
	else if (memcmp(pointeurHTTP, OPTIONS, sizeofSansSenti(OPTIONS)) == 0)
		type = OPTIONS;
	else if (memcmp(pointeurHTTP, TRACE, sizeofSansSenti(TRACE)) == 0)
		type = TRACE;

	if (niveauVerbo > SYNTHETIQUE){
		// Si on a trouvé une méthode précédemment
		if (strlen(type) > 0){
			// N'affiche pas le "\r\n" à la fin (d'où le "- 2")
			for (int i = 0; i < tailleHeader - 2; i++)
				printf("%c", *pointeurHTTP++);
		}

		// Sinon ce sont des données
		else
			printf("%s (%d bytes)", DATA, tailleHeader);
	}
	else{
		if (strlen(type) > 0)
			printf("%s", type);
		else
			printf("%s", DATA);
	}
}