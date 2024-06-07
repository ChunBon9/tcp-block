#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>

#define MAC_LEN 6
#define FIN_FLAG 1
#define RST_FLAG 4

typedef struct{
	uint8_t dstMac[6];
	uint8_t srcMac[6];
	uint16_t ethType;	
}ethHeader;

typedef struct{
	uint8_t ver_HeaderLen;
	uint8_t tos;
	uint16_t totalLen;
	uint16_t id;
	uint16_t ipFlag_FragOff;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t chksum;
	uint32_t srcAddr;
	uint32_t dstAddr;	
}ipHeader;

typedef struct{
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t seqNum;
	uint32_t ackNum;
	uint16_t dataOff_Reserved_Flags;
	uint16_t winSize;
	uint16_t chksum;
	uint16_t urgP; 
}tcpHeader;

typedef struct{
	ethHeader *eth;
	ipHeader *ip;
	tcpHeader *tcp;
	char *data;
}pkt;

typedef struct{
	uint32_t srcAddr; 
	uint32_t dstAddr;
	uint8_t reserved; 
	uint8_t protocol; 
	uint16_t tcpLen;
}pesudoHeader;

int getMacAddress(uint8_t *mac, char *dev) {
	int sock;
	struct ifreq ifr;		
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {		
		return 0;
	}	
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	for(int i=0; i<6; i++) {
		mac[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
	}
	close(sock);
	return 1;
}

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, char *pattern, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	memcpy(pattern, argv[2], strlen(argv[2]));
	pattern[strlen(argv[2])] = '\0';
	return true;
}

uint16_t parsePacket(pkt *p, const u_char *packet) {
	uint16_t headerSize = 0;
	
	p->eth = (ethHeader *)packet;
	headerSize += sizeof(ethHeader);
	
	p->ip = (ipHeader *)((uint8_t *)(p->eth) + headerSize);
	headerSize += (p->ip->ver_HeaderLen & 0x0F) << 2;
	
	p->tcp = (tcpHeader *)((uint8_t *)(p->eth) + headerSize);
	headerSize += (ntohs(p->tcp->dataOff_Reserved_Flags) >> 12) << 2;
	
	p->data = (char *)((uint8_t *)(p->eth) + headerSize);
	return headerSize;
}	

uint16_t calcChecksum(uint16_t *data, int len) {
	uint32_t chksum = 0;
	for(int i=0; i<len/2; i++) {
		chksum += ntohs(data[i]);
		if(chksum > 0xFFFF) {
			chksum %= 0x10000;
			chksum += 1;
		}
	}
	return (uint16_t)chksum;
}

void setChecksum(pkt *p, uint16_t len) {
	pesudoHeader pHeader;
	pHeader.srcAddr = p->ip->srcAddr;
	pHeader.dstAddr = p->ip->dstAddr;
	pHeader.reserved = 0;
	pHeader.protocol = p->ip->protocol;
	pHeader.tcpLen = htons(len);
	p->ip->chksum = 0;
	p->tcp->chksum = 0;
	
	p->ip->chksum = htons(calcChecksum((uint16_t *)p->ip, sizeof(ipHeader))^0xFFFF);
	
	uint32_t temp = calcChecksum((uint16_t *)&pHeader, sizeof(pesudoHeader)) + calcChecksum((uint16_t *)p->tcp, len + 1);
	temp > 0xFFFF ? temp = (temp%0x10000) + 1 : temp;
	p->tcp->chksum = htons((uint16_t)temp ^ 0xFFFF);
}

bool findPattern(char *data, char *pattern) {
	int len = strlen(data) - strlen(pattern); 
	for(int i=0; i<len; i++) {
		if(strncmp(data+i, pattern, strlen(pattern)) == 0) return true;
	}
	return false;
}

int main(int argc, char* argv[]) {
	char *redirect = "HTTP/1.0 302 Redirect\r\nLocation: http://github.com/ChunBon9\r\n\r\n";
	char pattern[1024];
	
	if (!parse(&param, pattern, argc, argv))
		return -1;
	pkt org;
	pkt forword;
	pkt backword;
	uint8_t forwordPacket[10000];
	uint8_t backwordPacket[10000];
	uint8_t myMac[MAC_LEN];
	uint16_t headerSize;
	uint16_t dataSize;
	uint16_t packetSize;
	
	getMacAddress(myMac, param.dev_);
	int fd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	struct sockaddr_ll dest;
	dest.sll_family = PF_PACKET;
	dest.sll_protocol = htons(ETH_P_IP);
	dest.sll_ifindex =  if_nametoindex(param.dev_);
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		headerSize = parsePacket(&org, packet);
		
		if(ntohs(org.eth->ethType) == 0x0800 && ((org.ip->ver_HeaderLen >> 4) == 0x4) && org.ip->protocol == 0x6) {
			packetSize = sizeof(ethHeader) + sizeof(ipHeader) + sizeof(tcpHeader);
			dataSize = ntohs(org.ip->totalLen) - (headerSize - sizeof(ethHeader));
			org.data[dataSize] = '\0';
			if(!findPattern(org.data, pattern)) continue;
			printf("GATCHA!\n");
			
			memcpy(forwordPacket, packet, packetSize);
			memcpy(backwordPacket, packet, packetSize);
			
			parsePacket(&forword, forwordPacket);
			parsePacket(&backword, backwordPacket);
			
			memcpy(forword.eth->srcMac, myMac, MAC_LEN);
			memcpy(backword.eth->srcMac, myMac, MAC_LEN);
			memcpy(backword.eth->dstMac, org.eth->srcMac, MAC_LEN);
			
			forword.ip->totalLen = htons(sizeof(ipHeader) + sizeof(tcpHeader));
			backword.ip->totalLen = htons(sizeof(ipHeader) + sizeof(tcpHeader) + strlen(redirect));
			
			backword.ip->ttl = 128;
			
			backword.ip->srcAddr = org.ip->dstAddr;
			backword.ip->dstAddr = org.ip->srcAddr;
			
			forword.tcp->urgP = 0;
			backword.tcp->urgP = 0;
			
			backword.tcp->srcPort = org.tcp->dstPort;
			backword.tcp->dstPort = org.tcp->srcPort;
			
			forword.tcp->seqNum = htonl(ntohl(org.tcp->seqNum) + dataSize);
			backword.tcp->seqNum = htonl(ntohl(org.tcp->ackNum));
			backword.tcp->ackNum = htonl(ntohl(org.tcp->seqNum) + dataSize);
			
			forword.tcp->dataOff_Reserved_Flags = htons((sizeof(tcpHeader) >> 2) << 12 | (16 | RST_FLAG));
			backword.tcp->dataOff_Reserved_Flags = htons((sizeof(tcpHeader) >> 2) << 12 | (16 | FIN_FLAG));
			
			memcpy(backword.data, redirect, strlen(redirect));
			backword.data[strlen(redirect)] = 0;
			
			setChecksum(&forword, (uint16_t)sizeof(tcpHeader));
			setChecksum(&backword, (uint16_t)(sizeof(tcpHeader) + strlen(redirect)));
			
			memcpy(dest.sll_addr, forword.eth->dstMac, MAC_LEN);
			if(sendto(fd, forwordPacket, packetSize, 0, (struct sockaddr *)&dest, sizeof(dest)) <= 0) perror("forword");
			memcpy(dest.sll_addr, backword.eth->dstMac, MAC_LEN);
			if(sendto(fd, backwordPacket, packetSize + strlen(redirect), 0, (struct sockaddr *)&dest, sizeof(dest)) <= 0)  perror("backword");
		}
	}
	pcap_close(pcap);
}
