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
#define UDP_HEADER_LEN 8

#define LOG 1

#pragma pack(1)

void dump_packets(unsigned char* buffer) {
	ip_packet* packet = (ip_packet*)buffer;

	int ipLenght = (packet->versionAndLength & 0b00001111)* (packet->versionAndLength >> 4);

	if (packet->protocol == 6) {
		// tcp
	}
	else if (packet->protocol == 17) {

		unsigned short sourcePort = *(buffer + ipLenght+1) + *(buffer + ipLenght + 2);
		unsigned short destPort = *(buffer + ipLenght + 3) + *(buffer + ipLenght + 4);

		if (destPort == 53) {
#ifdef LOG
			printf("IP Version: %u\n", packet->versionAndLength >> 4);

			printf("Length: %u\n", ipLenght);

			printf("Source IP: %u.%u.%u.%u\n", *(buffer + ipLenght - 8), *(buffer + ipLenght - 7),
				*(buffer + ipLenght - 6), *(buffer + ipLenght - 5));

			printf("Dest IP: %u.%u.%u.%u\n", *(buffer + ipLenght - 4), *(buffer + ipLenght - 3),
				*(buffer + ipLenght - 2), *(buffer + ipLenght - 1));

			// udp
			printf("UDP Hdr:\n");

			// dns
			printf("DNS:\n");

			printf("source port: %u\n", sourcePort);
			printf("dest port: %u\n", destPort);
#endif

			unsigned char udpLength = *(buffer + ipLenght + 4) + *(buffer + ipLenght + 5);

			unsigned short transactionId = *(buffer + ipLenght + UDP_HEADER_LEN+1) + *(buffer + ipLenght + UDP_HEADER_LEN + 2);

#ifdef LOG
			printf("Transaction ID: %u\n", transactionId);
#endif

			// TODO: send dns spoof replay

			// domain section
			unsigned char* dnsRecord = (unsigned char*)(buffer + ipLenght + UDP_HEADER_LEN + 12);

#ifdef LOG
			for (int i = 0; i < udpLength; i++) {
				printf("%c", dnsRecord[i]);
			}

			printf("\n\n\n");
#endif

		}
	}
}

void start_sniffing(char* interface_ip) {
	WSAData wsaData;
	int stratupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (stratupResult != 0) {
		fprintf(stderr, "while calling WSAStartup: %u\n", WSAGetLastError());
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

	start_sniffing(argv[1]);
}