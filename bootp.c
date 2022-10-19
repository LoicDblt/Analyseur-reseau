#include "bootpHeader.h"

void gestionBootp(const u_char* paquet, int size_udp){
	const struct bootp* bootp;
	bootp = (struct bootp*)(paquet + size_udp);

	printf("\n\n");
	titreViolet("Informations Bootp");
	printf(JAUNE);
	printf("Code op : ");
	if (bootp->bp_op == BOOTREQUEST){
		printf("REQUEST\n");
	}
	else if (bootp->bp_op == BOOTREPLY){
		printf("REPLY\n");
	}
	else{
		printf("Inconnu\n");
	}
	printf("Type addr matériel : %d\n", bootp->bp_htype);
	printf("Longueur addr : %d\n", bootp->bp_hlen);
	printf("Cmpt sauts : %d\n", bootp->bp_hops);
	printf("Id transaction : %u\n", bootp->bp_xid);
	printf("Nbr de secondes : %hu\n", bootp->bp_secs);
	printf("IP client : %s\n", inet_ntoa(bootp->bp_ciaddr));
	printf("\"votre\" IP : %s\n", inet_ntoa(bootp->bp_yiaddr));
	printf("IP serveur : %s\n", inet_ntoa(bootp->bp_siaddr));
	printf("IP gateway : %s\n", inet_ntoa(bootp->bp_giaddr));
	printf("Addr matériel client : %s\n", bootp->bp_chaddr);
	printf("Nom machine du serveur : %s\n", bootp->bp_sname);
	printf("Nom du fichier bootp : %s\n", bootp->bp_file);
	printf("Info spécifique vendeur : %s\n", bootp->bp_vend);

	/** Gérer DHCP ICI (voir avec un bootp.h de Linux au lieu de MacOS)*/
}