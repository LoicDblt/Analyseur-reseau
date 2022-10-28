#include "../inc/bootpHeader.h"

void affichageIP(u_int8_t* pointeur, u_int8_t longueur){
	int nbrPoints = 0;
	for (int i = 0; i < longueur; i++){
		printf("%d", pointeur[i]);

		if (nbrPoints/3){
			nbrPoints = 0;
			if (i+1 < longueur)
				printf("\n\t\t");
		}
		else{
			printf(".");
			nbrPoints++;
		}
	}
}

void affichageString(u_int8_t* pointeur, u_int8_t longueur){
	for (int i = 0; i < longueur; i++)
		putchar(pointeur[i]);
}

void gestionBootP(const u_char* paquet, int size_udp){
	const struct bootp* bootp = (struct bootp*)(paquet + size_udp);

	printf("\n\n");
	titreViolet("Bootp");
	printf(JAUNE);
	printf("Code op : ");
	if (bootp->bp_op == BOOTREQUEST)
		printf("REQUEST\n");
	else if (bootp->bp_op == BOOTREPLY)
		printf("REPLY\n");
	else
		printf("Inconnu\n");

	printf("Type addr matériel : 0x%02x\n", bootp->bp_htype);
	printf("Longueur addr : %d\n", bootp->bp_hlen);
	printf("Compteur sauts : %d\n", bootp->bp_hops);
	printf("Id transaction : 0x%08x\n", ntohl(bootp->bp_xid));
	printf("Nbr de secondes : %hu\n", bootp->bp_secs);
	printf("Flag : ");
	switch(ntohs(bootp->bp_flags)){
		/* Broadcast */
		case BROADCAST:
			printf("Broadcast\n");
			break;

		/* Unicast */
		case UNICAST:
			printf("Unicast\n");
			break;

		/* Non pris en charge */
		default:
			printf("Non pris en charge\n");
			break;
	}
	printf("IP client : %s\n", inet_ntoa(bootp->bp_ciaddr));
	printf("\"Votre\" IP : %s\n", inet_ntoa(bootp->bp_yiaddr));
	printf("IP serveur : %s\n", inet_ntoa(bootp->bp_siaddr));
	printf("IP gateway : %s\n", inet_ntoa(bootp->bp_giaddr));
	printf("Addr matériel client : ");
	affichageAdresseMac(bootp->bp_chaddr);

	printf("Nom machine du serveur : ");
	if (strlen((char*) bootp->bp_sname) == 0)
		printf("Non fourni\n");
	else
		printf("%s\n", bootp->bp_sname);

	printf("Nom du fichier bootp : ");
	if (strlen((char*) bootp->bp_file) == 0)
		printf("Non fourni\n");
	else
		printf("%s\n", bootp->bp_file);

	// Vérification du magic cookie
	printf("Magic cookie : ");
	u_int8_t* copieVend = (u_int8_t*) bootp->bp_vend;
	const u_int8_t magicCookie[4] = VM_RFC1048;

	if (memcmp(copieVend, magicCookie, 4) == 0){
		printf("DHCP\n");

		// On se déplace de la taille du magic cookie
		copieVend += 4;

		// Principe du Type Len Value (TLV)
		u_int8_t type, longueur;

		while(1){
			printf("\t");

			// On avance d'un bit (Type puis Longueur et enfin Valeur)
			type = *copieVend++;
			longueur = *copieVend++;

			switch(type){
				/* Subnet mask */
				case TAG_SUBNET_MASK:
					printf("Masque sous-réseau : ");
					affichageIP(copieVend, longueur);
					break;

				/* Router */
				case TAG_GATEWAY:
					printf("Addr gateway : ");
					affichageIP(copieVend, longueur);
					break;

				/* DNS */
				case TAG_DOMAIN_SERVER:
					printf("DNS :\t");
					affichageIP(copieVend, longueur);
					break;

				/* Hostname */
				case TAG_HOSTNAME:
					printf("Hostname : ");
					affichageString(copieVend, longueur);
					break;

				/* Domain name */
				case TAG_DOMAINNAME:
					printf("Nom domaine : ");
					affichageString(copieVend, longueur);
					break;

				/* Broadcast address */
				case TAG_BROAD_ADDR:
					printf("Addr broadcast : ");
					affichageIP(copieVend, longueur);
					break;

				/* Requested IP address */
				case TAG_REQUESTED_IP:
					printf("IP demandée : ");
					affichageIP(copieVend, longueur);
					break;

				/* Lease time */
				case TAG_IP_LEASE:
					printf("Durée attribution IP : %ds", ntohl(*((int*)copieVend)));
					break;

				/* DHCP message type */
				case TAG_DHCP_MESSAGE: {
					printf("Message DHCP : ");

					switch(*copieVend){
						/* Discover */
						case DHCPDISCOVER:
							printf("Discover");
							break;

						/* Offer */
						case DHCPOFFER:
							printf("Offer");
							break;

						/* Request */
						case DHCPREQUEST:
							printf("Request");
							break;

						/* Ack */
						case DHCPACK:
							printf("Ack");
							break;

						/* Release */
						case DHCPRELEASE:
							printf("Release");
							break;

						/* Non pris en charge */
						default:
							printf("Non pris en charge (%d)", *copieVend);
							break;
					}
					break;
				}

				/* Server identifier */
				case TAG_SERVER_ID:
					printf("Identifiant serveur : ");
					affichageIP(copieVend, longueur);
					break;

				/* Parameter request list */
				case TAG_PARM_REQUEST:
					printf("Demande liste des paramètres");
					break;

				/* Client identifier */
				case TAG_CLIENT_ID:
					printf("Identifiant client : ");
					affichageString(copieVend, longueur);
					break;

				/* Fin des options */
				case TAG_END:
					return;

				/* Non pris en charge */
				default:
					printf("Option (%d) non prise en charge", type);
					break;
			}
			printf("\n");

			// On passe au Type suivant
			copieVend += longueur;
		}
	}

	// Si le magic cookie n'est pas reconnu
	else
		printf("Non reconnu");
}