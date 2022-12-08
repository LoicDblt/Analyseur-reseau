#ifndef MAIN_H
#define MAIN_H

/************** INCLUDES **************/

#include <unistd.h>
#include <pcap.h>

#include "ethernet.h"
#include "utile.h"

/************** CONSTANTE *************/

#define NBR_PAQUET_INF_0	0
#define NBR_PAQUET_INF_1	-1
#define VERBOSITE_DEFAUT	1

/*************** GLOBAL ***************/

extern int niveauVerbo;

#endif