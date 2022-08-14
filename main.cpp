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


char* getIpAddress(){
	 int fd;
	 struct ifreq ifr;
	 fd = socket(AF_INET, SOCK_DGRAM, 0);
	 ifr.ifr_addr.sa_family = AF_INET; //get IPv4
	 strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ-1); //ip attatce to enp0s3

	 ioctl(fd, SIOCGIFADDR, &ifr);
	 close(fd);
	 return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

 char* getMacAddress()
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	char* mac ;	
	strcpy(s.ifr_name, "enp0s3");
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
	return mac;
}


int sendArpRequest(char* myIp, char* myMac, char* sender_ip, pcap_t* handle){
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	char* mac ;	
	strcpy(s.ifr_name, "enp0s3");
	ioctl(fd, SIOCGIFHWADDR, &s);
	mac = reinterpret_cast<char *>(s.ifr_addr.sa_data);

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
	(unsigned char)s.ifr_hwaddr.sa_data[0],
	(unsigned char)s.ifr_hwaddr.sa_data[1],
	(unsigned char)s.ifr_hwaddr.sa_data[2],
	(unsigned char)s.ifr_hwaddr.sa_data[3],
	(unsigned char)s.ifr_hwaddr.sa_data[4],
	(unsigned char)s.ifr_hwaddr.sa_data[5]);
	
	
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //unknown mac
	packet.eth_.smac_ = Mac(mac); //source mac (my mac)
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	
	printf("%s",myMac);
	
	packet.arp_.smac_ = Mac(mac); // source mac(my mac)
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


Mac getSenderMac(char* dev,char* senderIP){
    struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	char* mac ;	
	strcpy(s.ifr_name, "enp0s3");
	ioctl(fd, SIOCGIFHWADDR, &s);
	mac = reinterpret_cast<char *>(s.ifr_addr.sa_data);

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
	(unsigned char)s.ifr_hwaddr.sa_data[0],
	(unsigned char)s.ifr_hwaddr.sa_data[1],
	(unsigned char)s.ifr_hwaddr.sa_data[2],
	(unsigned char)s.ifr_hwaddr.sa_data[3],
	(unsigned char)s.ifr_hwaddr.sa_data[4],
	(unsigned char)s.ifr_hwaddr.sa_data[5]);

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
		printf("\n\n\n%u bytes captured\n", header->caplen);

		
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
		
		printf("%04x\n", eth_type);
		if (eth_type == 0x0806){
			if(dmac==Mac(mac) && sip==Ip(senderIP))
				return smac;
			printf("%04x\n", eth_type);
			printf("%02x\n", op_type);		
		}	 
		
	}
      pcap_close(pcap);

}


int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];	
	char* sender_ip = argv[2]; //victim ip
	char* target_ip = argv[3]; //gateway ip 	
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr){
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	//get ip address
	char* myIp = getIpAddress();
	char* myMacAddress = getMacAddress();

	
	printf("%s\n",myIp);
	printf("%s",myMacAddress);
    
	int request_result = sendArpRequest(myIp, myMacAddress, sender_ip, handle);
	
	Mac src_mac = getSenderMac(dev, sender_ip);
}




