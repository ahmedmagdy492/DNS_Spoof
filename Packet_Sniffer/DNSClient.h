#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>

#include "Util.h"

char* prepare_dns_packet(char* spoofDomain, int spoofDomainLen, int* packetLen, unsigned short transId, char spoofIP[]);

int send_dns_packet(char* packet, int len, int port, char ip[4]);