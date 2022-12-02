#ifndef IPV6_H
#define IPV6_H

/************** INCLUDES **************/

#include <netinet/ip6.h>

#include "ipv4.h"

// Source : <netinet/ip6.h> de MacOS
#if BYTE_ORDER == BIG_ENDIAN
	#define IPV6_FLOWINFO_MASK	0x0fffffff /* flow info (28 bits) */
	#define IPV6_FLOWLABEL_MASK	0x000fffff /* flow label (20 bits) */
	#define IPV6_FLOW_ECN_MASK	0x00300000 /* the 2 ECN bits */
#else
#if BYTE_ORDER == LITTLE_ENDIAN
	#define IPV6_FLOWINFO_MASK	0xffffff0f /* flow info (28 bits) */
	#define IPV6_FLOWLABEL_MASK	0xffff0f00 /* flow label (20 bits) */
	#define IPV6_FLOW_ECN_MASK	0x00003000 /* the 2 ECN bits */
#endif /* LITTLE_ENDIAN */
#endif

/************** FONCTION **************/

// Fonction de gestion du protocole IPv6
void gestionIPv6(const u_char* paquet, const int offset);

#endif