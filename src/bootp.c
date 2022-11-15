#include "../inc/bootpHeader.h"

void affichageString(const u_int8_t* pointeur, const u_int8_t longueur){
	for (unsigned int i = 0; i < longueur; i++){
		printf("%c", *pointeur++);
	}
}

void affichageDuree(const u_int8_t* pointeur){
	printf("%ds", ntohl(*((int*) pointeur)));
}

void affichageParam(const u_int8_t* pointeur){
	switch (*pointeur){
		/* Subnet mask */
		case TAG_SUBNET_MASK:
			printf("(%d)\tSubnet mask", *pointeur);
			break;

		/* Offset */
		case TAG_TIME_OFFSET:
			printf("(%d)\tTime offset", *pointeur);
			break;

		/* Router */
		case TAG_GATEWAY:
			printf("(%d)\tGateway", *pointeur);
			break;

		/* DNS */
		case TAG_DOMAIN_SERVER:
			printf("(%d)\tDNS", *pointeur);
			break;

		/* Hostname */
		case TAG_HOSTNAME:
			printf("(%d)\tHostname", *pointeur);
			break;

		/* Domain name */
		case TAG_DOMAINNAME:
			printf("(%d)\tDomain name", *pointeur);
			break;

		/* Broadcast address */
		case TAG_BROAD_ADDR:
			printf("(%d)\tBroadcast address", *pointeur);
			break;

		/* Requested IP address */
		case TAG_REQUESTED_IP:
			printf("(%d)\tRequested IP", *pointeur);
			break;

		/* Lease time */
		case TAG_IP_LEASE:
			printf("(%d)\tIP lease", *pointeur);
			break;

		/* Server identifier */
		case TAG_SERVER_ID:
			printf("(%d)\tServer ID", *pointeur);
			break;

		/* Renewal time */
		case TAG_RENEWAL_TIME:
			printf("(%d)\tRenewal time", *pointeur);
			break;

		/* Rebind time */
		case TAG_REBIND_TIME:
			printf("(%d)\tRebind time", *pointeur);
			break;

		/* Client identifier */
		case TAG_CLIENT_ID:
			printf("(%d)\tClient ID", *pointeur);
			break;

		/* Non pris en charge */
		default:
			printf("(%d)\tUnsupported option", *pointeur);
			break;
	}
}

void gestionBootP(const u_char* paquet, const int offset){
	const struct bootp* bootp = (struct bootp*)(paquet + offset);

	titreViolet("BootP");

	if (niveauVerbo > SYNTHETIQUE){
		printf("Message type : ");
		switch (bootp->bp_op){
			/* Bootrequest */
			case BOOTREQUEST:
				printf("Request (%d)", BOOTREQUEST);
				break;

			/* Bootreply */
			case BOOTREPLY:
				printf("Reply (%d)", BOOTREPLY);
				break;

			/* Inconnu */
			default:
				printf("Unknown");
				break;
		}

		printf("\nHardware type : ");
		if (bootp->bp_htype == ETHERNET)
			printf("Ethernet (0x%02x)\n", bootp->bp_htype);
		else
			printf("Unknown (0x%02x)\n", bootp->bp_htype);

		printf("Hardware adress length : %d\n", bootp->bp_hlen);
		printf("Hops : %d\n", bootp->bp_hops);
		printf("Transaction ID : 0x%08x\n", ntohl(bootp->bp_xid));
		printf("Seconds elapsed : %u\n", bootp->bp_secs);

		printf("Flags : ");
		switch (ntohs(bootp->bp_flags)){
			/* Broadcast */
			case BROADCAST:
				printf("Broadcast");
				break;

			/* Unicast */
			case UNICAST:
				printf("Unicast");
				break;

			/* Non pris en charge */
			default:
				printf("Unknown");
				break;
		}
		printf(" (0x%04x)\n", ntohs(bootp->bp_flags));

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
	}


	// Vérification du magic cookie

	if (niveauVerbo > CONCIS)
		printf("Magic cookie : ");

	u_int8_t* pointeurDCHP = (u_int8_t*) bootp->bp_vend;
	const u_int8_t magicCookie[4] = VM_RFC1048;

	if (memcmp(pointeurDCHP, magicCookie, sizeof(magicCookie)) == 0){
		if (niveauVerbo > CONCIS)
			printf("DHCP");

		titreViolet("DHCP");

		// Principe du Type Len Value (TLV)
		u_int8_t type = 0, longueur;
		pointeurDCHP += 4;

		while (niveauVerbo > CONCIS && type != TAG_END){
			// On avance ("Type", puis "Longueur" et enfin "Valeur")
			type = *pointeurDCHP++;
			longueur = *pointeurDCHP++;

			if (type != TAG_END && niveauVerbo > SYNTHETIQUE)
				printf("(%d) ", type);

			switch (type){
				/* Subnet mask */
				case TAG_SUBNET_MASK:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Subnet mask : ");
						affichageAdresseIPv4(pointeurDCHP, longueur);
					}
					break;

				/* Offset */
				case TAG_TIME_OFFSET:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Time offset : ");
						affichageDuree(pointeurDCHP);
					}
					break;

				/* Router */
				case TAG_GATEWAY:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Router : ");
						affichageAdresseIPv4(pointeurDCHP, longueur);
					}
					break;

				/* DNS */
				case TAG_DOMAIN_SERVER:
					if (niveauVerbo > SYNTHETIQUE){
						printf("DNS : ");

						// Pour gérer plusieurs DNS
						unsigned int nbrDNS = longueur/TAILLE_IPv4;
						for (unsigned int i = 0; i < nbrDNS; i++){
							if (i > 0)
								printf("\n\t  ");
							affichageAdresseIPv4(pointeurDCHP, TAILLE_IPv4);
							pointeurDCHP += TAILLE_IPv4;
						}
						longueur -= nbrDNS * TAILLE_IPv4;
					}
					break;

				/* Hostname */
				case TAG_HOSTNAME:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Hostname : ");
						affichageString(pointeurDCHP, longueur);
					}
					break;

				/* Domain name */
				case TAG_DOMAINNAME:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Domain name : ");
						affichageString(pointeurDCHP, longueur);
					}
					break;

				/* Broadcast address */
				case TAG_BROAD_ADDR:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Broadcast address : ");
						affichageAdresseIPv4(pointeurDCHP, longueur);
					}
					break;

				/* Requested IP address */
				case TAG_REQUESTED_IP:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Requested IP : ");
						affichageAdresseIPv4(pointeurDCHP, longueur);
					}
					break;

				/* Lease time */
				case TAG_IP_LEASE:
					if (niveauVerbo > SYNTHETIQUE){
						printf("IP lease : ");
						affichageDuree(pointeurDCHP);
					}
					break;

				/* DHCP message type */
				case TAG_DHCP_MESSAGE: {
					printf("DHCP message : ");

					switch (*pointeurDCHP){
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
							printf("Unsupported");
							break;
					}
					if (niveauVerbo > SYNTHETIQUE)
						printf(" (%d)", *pointeurDCHP);
					break;
				}

				/* Server identifier */
				case TAG_SERVER_ID:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Server ID : ");
						affichageAdresseIPv4(pointeurDCHP, longueur);
					}
					break;

				/* Parameter request list */
				case TAG_PARM_REQUEST:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Parameters request :");
						for (unsigned int i = 0; i < longueur; i++){
							printf("\n\t");
							affichageParam(&pointeurDCHP[i]);
						}
					}
					break;

				/* Renewal time */
				case TAG_RENEWAL_TIME:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Renewal time : ");
						affichageDuree(pointeurDCHP);
					}
					break;

				/* Rebind time */
				case TAG_REBIND_TIME:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Rebind time : ");
						affichageDuree(pointeurDCHP);
					}
					break;

				/* Client identifier */
				case TAG_CLIENT_ID:
					if (niveauVerbo > SYNTHETIQUE){
						printf("Client ID : ");
						affichageString(pointeurDCHP, longueur);
					}
					break;

				/* End of options */
				case TAG_END:
					return;

				/* Non pris en charge */
				default:
					if (niveauVerbo > SYNTHETIQUE)
						printf("Unsupported option");
					break;
			}
			if (niveauVerbo > SYNTHETIQUE)
				printf("\n");

			// On passe au "Type" suivant
			pointeurDCHP += longueur;
		}
	}

	// Si le magic cookie n'est pas reconnu
	else{
		if (niveauVerbo > SYNTHETIQUE)
			printf("Unknown");
	}
}