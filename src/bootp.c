#include "../inc/bootpHeader.h"

void affichageIP(const u_int8_t* pointeur, const u_int8_t longueur){
	int nbrPoints = 0;
	for (int i = 0; i < longueur; i++){
		printf("%d", pointeur[i]);

		if (nbrPoints/3){
			nbrPoints = 0;
			if (i+1 < longueur)
				printf(" and ");
		}
		else{
			printf(".");
			nbrPoints++;
		}
	}
}

void affichageString(const u_int8_t* pointeur, const u_int8_t longueur){
	for (int i = 0; i < longueur; i++){
		if (putchar(pointeur[i]) == EOF)
			fprintf(stderr, "|Error| AffichageString | putchar");
	}
}

void affichageDurée(const char* message, const u_int8_t* pointeur){
	printf("%s : %ds", message, ntohl(*((int*) pointeur)));
}

void gestionBootP(const u_char* paquet, const int size_udp){
	const struct bootp* bootp = (struct bootp*)(paquet + size_udp);

	titreViolet("BootP");
	printf(JAUNE);
	printf("Operation : ");
	switch(bootp->bp_op){
		/* Bootrequest */
		case BOOTREQUEST:
			printf("Request");
			break;

		/* Bootreply */
		case BOOTREPLY:
			printf("Reply");
			break;

		/* Inconnu */
		default:
			printf("Inconnu");
	}
	printf("\nHardware type : 0x%02x\n", bootp->bp_htype);
	printf("Hardware adress length : %d\n", bootp->bp_hlen);
	printf("Hops : %d\n", bootp->bp_hops);
	printf("Transaction ID : 0x%08x\n", ntohl(bootp->bp_xid));
	printf("Seconds elapsed : %hu\n", bootp->bp_secs);
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
	printf("Client IP address: %s\n", inet_ntoa(bootp->bp_ciaddr));
	printf("\"Your\" IP address: %s\n", inet_ntoa(bootp->bp_yiaddr));
	printf("Next server IP address : %s\n", inet_ntoa(bootp->bp_siaddr));
	printf("Relay agent IP address : %s\n", inet_ntoa(bootp->bp_giaddr));
	printf("Client MAC address : ");
	affichageAdresseMAC(bootp->bp_chaddr);

	printf("\nServer host name : ");
	if (strlen((char*) bootp->bp_sname) == 0)
		printf("Not given\n");
	else
		printf("%s\n", bootp->bp_sname);

	printf("Boot file name : ");
	if (strlen((char*) bootp->bp_file) == 0)
		printf("Not given\n");
	else
		printf("%s\n", bootp->bp_file);

	// Vérification du magic cookie
	printf("Magic cookie : ");

	u_int8_t* copieVend = (u_int8_t*) bootp->bp_vend;
	const u_int8_t magicCookie[4] = VM_RFC1048;

	if (memcmp(copieVend, magicCookie, 4) == 0){
		printf("DHCP");

		titreViolet("DHCP");
		printf(JAUNE);

		// On se déplace de la taille du magic cookie
		copieVend += 4;

		// Principe du Type Len Value (TLV)
		u_int8_t type, longueur;

		while(1){

			// On avance d'un bit (Type puis Longueur et enfin Valeur)
			type = *copieVend++;
			longueur = *copieVend++;

			switch(type){
				/* Subnet mask */
				case TAG_SUBNET_MASK:
					printf("Subnet mask : ");
					affichageIP(copieVend, longueur);
					break;

				/* Offset */
				case TAG_TIME_OFFSET:
					affichageDurée("Time offset", copieVend);
					break;

				/* Router */
				case TAG_GATEWAY:
					printf("Gateway : ");
					affichageIP(copieVend, longueur);
					break;

				/* DNS */
				case TAG_DOMAIN_SERVER:
					printf("DNS : ");
					affichageIP(copieVend, longueur);
					break;

				/* Hostname */
				case TAG_HOSTNAME:
					printf("Hostname : ");
					affichageString(copieVend, longueur);
					break;

				/* Domain name */
				case TAG_DOMAINNAME:
					printf("Domain name : ");
					affichageString(copieVend, longueur);
					break;

				/* Broadcast address */
				case TAG_BROAD_ADDR:
					printf("Broadcast address : ");
					affichageIP(copieVend, longueur);
					break;

				/* Requested IP address */
				case TAG_REQUESTED_IP:
					printf("Requested IP : ");
					affichageIP(copieVend, longueur);
					break;

				/* Lease time */
				case TAG_IP_LEASE:
					affichageDurée("IP lease", copieVend);
					break;

				/* DHCP message type */
				case TAG_DHCP_MESSAGE: {
					printf("DHCP message : ");

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

						/* Decline */
						case DHCPDECLINE:
							printf("Decline");
							break;

						/* Ack */
						case DHCPACK:
							printf("Ack");
							break;

						/* Nak */
						case DHCPNAK:
							printf("Nak");
							break;

						/* Release */
						case DHCPRELEASE:
							printf("Release");
							break;

						/* Non pris en charge */
						default:
							printf("Not supported (%d)", *copieVend);
							break;
					}
					break;
				}

				/* Server identifier */
				case TAG_SERVER_ID:
					printf("Server ID : ");
					affichageIP(copieVend, longueur);
					break;

				/* Parameter request list */
				case TAG_PARM_REQUEST:
					printf("Parameters request");
					break;

				/* Renewal time */
				case TAG_RENEWAL_TIME:
					affichageDurée("Renewal time", copieVend);
					break;

				/* Rebind time */
				case TAG_REBIND_TIME:
					affichageDurée("Rebind time", copieVend);
					break;

				/* Client identifier */
				case TAG_CLIENT_ID:
					printf("Client ID : ");
					affichageString(copieVend, longueur);
					break;

				/* Fin des options */
				case TAG_END:
					return;

				/* Non pris en charge */
				default:
					printf("Unsupported option (%d)", type);
					break;
			}
			printf("\n");

			// On passe au Type suivant
			copieVend += longueur;
		}
	}

	// Si le magic cookie n'est pas reconnu
	else
		printf("Unknown");
}