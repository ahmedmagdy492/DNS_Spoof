#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <stdint.h>

#pragma comment(lib, "Ws2_32.lib")

#define ETH_HDR_LEN 14
#define IP_HDR_LEN 24

int main(int argc, char** argv) {

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <ip-of-interface>\n", argv[0]);
		exit(-1);
	}

	WSAData wsaData;
	int stratupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (stratupResult != 0) {
		fprintf(stderr, "while calling WSAStartup: %u", WSAGetLastError());
		exit(-1);
	}

	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	if (sock == INVALID_SOCKET) {
		fprintf(stderr, "While creating socket: %u\n",	WSAGetLastError());
		exit(-1);
	}

	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
	inet_pton(AF_INET, argv[1], &(addr.sin_addr.S_un.S_addr));

	int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (result == SOCKET_ERROR) {
		fprintf(stderr, "while binding: %u", WSAGetLastError());
		exit(-1);
	}

	int value = RCVALL_IPLEVEL;
	DWORD out = 0;
	result = WSAIoctl(sock, SIO_RCVALL, &value, sizeof(value), NULL, 0, &out, NULL, NULL);
	if (result == SOCKET_ERROR) {
		fprintf(stderr, "while calling WSAIoctl(): %u", WSAGetLastError());
		exit(-1);
	}

	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * 100000);

	if (!buffer) {
		fprintf(stderr, "while allocating buffer for recv");
		exit(-1);
	}
	//buffer[BUFFER_OFFSET_ETH + 12] = 0x08;
	//struct pcap_sf_pkthdr* pkt = (struct pcap_sf_pkthdr*)buffer;

	while (1) {
		memset(buffer, 0, 100000);
		result = recv(sock, (char*)buffer, 100000, 0);

		if (result == SOCKET_ERROR) {
			fprintf(stderr, "while calling recv(): %u", WSAGetLastError());
			exit(-1);
		}

		for (int i = 0; i < 100000; i+=2) {
			if (buffer[i] != 0) {
				printf("%x%x ", buffer[i], buffer[i+1]);
			}
		}
		printf("\n\n\n");
	}

	free(buffer);

	closesocket(sock);

	WSACleanup();
}