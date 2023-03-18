#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <stdint.h>

#pragma comment(lib, "Ws2_32.lib")

struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct pcap_sf_pkthdr {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
};

typedef struct ip_packet {
	unsigned char versionAndLength;
	unsigned char servicesField;
	unsigned short totalLength;
	unsigned short id;
	unsigned short flags;
	unsigned char timeToLive;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char source[4];
	unsigned char dst[4];
} 
ip_packet;

#define BUFFER_SIZE_HDR sizeof(struct pcap_sf_pkthdr)
#define BUFFER_SIZE_ETH 14
#define BUFFER_SIZE_PKT ((256*256) - 1)
#define BUFFER_SIZE_IP (BUFFER_SIZE_PKT - BUFFER_SIZE_ETH)
#define BUFFER_OFFSET_ETH sizeof(struct pcap_sf_pkthdr)
#define BUFFER_OFFSET_IP (BUFFER_OFFSET_ETH + BUFFER_SIZE_ETH)

void dump_packets(unsigned char* buffer) {
	ip_packet* packet = (ip_packet*)buffer;

	printf("IP Version: %u\n", packet->versionAndLength >> 4);

	int length = (packet->versionAndLength & 0b00001111)* (packet->versionAndLength >> 4);

	printf("Length: %u\n", length);

	printf("Source IP: %u.%u.%u.%u\n", *(buffer + length - 8), *(buffer + length - 7), 
		*(buffer + length - 6), *(buffer + length - 5));

	printf("Dest IP: %u.%u.%u.%u\n", *(buffer + length - 4), *(buffer + length - 3),
		*(buffer + length - 1), *(buffer + length - 1));
}

void start_sniff(char* interface_ip) {
	WSAData wsaData;
	int stratupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (stratupResult != 0) {
		fprintf(stderr, "while calling WSAStartup: %u", WSAGetLastError());
		exit(-1);
	}

	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	if (sock == INVALID_SOCKET) {
		fprintf(stderr, "While creating socket: %u\n", WSAGetLastError());
		exit(-1);
	}

	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
	inet_pton(AF_INET, interface_ip, &(addr.sin_addr.S_un.S_addr));

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

	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * (BUFFER_SIZE_HDR + BUFFER_SIZE_PKT));

	if (!buffer) {
		fprintf(stderr, "while allocating buffer for recv");
		exit(-1);
	}

	while (1) {
		memset(buffer, 0, BUFFER_SIZE_HDR + BUFFER_SIZE_PKT);
		result = recv(sock, (char*)buffer + BUFFER_OFFSET_IP, BUFFER_SIZE_IP, 0);

		if (result == SOCKET_ERROR) {
			fprintf(stderr, "while calling recv(): %u", WSAGetLastError());
			exit(-1);
		}

		dump_packets(buffer + BUFFER_OFFSET_IP);
		printf("\n\n\n");
	}

	free(buffer);

	closesocket(sock);

	WSACleanup();
}

int main(int argc, char** argv) {

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <ip-of-interface>\n", argv[0]);
		exit(-1);
	}

	start_sniff(argv[1]);
}