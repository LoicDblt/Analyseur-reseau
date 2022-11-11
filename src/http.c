#include "../inc/http.h"

void gestionHTTP(const u_char* paquet, const int offset, int tailleHeader){
	// On se place après l'entête TCP
	u_int8_t* pointeurHTTP =  (u_int8_t*) paquet + offset;


	// Si on trouve une méthode d'HTTP (RFC 7231), on affiche le contenu
	if (
		memcmp(pointeurHTTP, GET, sizeofSansSenti(GET)) == 0 ||
		memcmp(pointeurHTTP, HEAD, sizeofSansSenti(HEAD)) == 0 ||
		memcmp(pointeurHTTP, POST, sizeofSansSenti(POST)) == 0 ||
		memcmp(pointeurHTTP, PUT, sizeofSansSenti(PUT)) == 0 ||
		memcmp(pointeurHTTP, DELETE, sizeofSansSenti(DELETE)) == 0 ||
		memcmp(pointeurHTTP, CONNECT, sizeofSansSenti(CONNECT)) == 0 ||
		memcmp(pointeurHTTP, OPTIONS, sizeofSansSenti(OPTIONS)) == 0 ||
		memcmp(pointeurHTTP, TRACE, sizeofSansSenti(TRACE)) == 0
	){
		titreViolet("HTTP");

		for (int i = 0; i < tailleHeader; i++)
			printf("%c", *pointeurHTTP++);
	}
}