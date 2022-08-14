#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

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


int sendArpRequest(char* sender_ip, char* target_ip, pcap_t* handle){
	
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac("08:00:27:32:d5:9a");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("08:00:27:32:d5:9a");
	packet.arp_.sip_ = htonl(Ip(sender_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(target_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	pcap_close(handle);
	return 1;
}



int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];	
	char* sender_ip = argv[2];
	char* target_ip = argv[3]; 	
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr){
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	//get ip address
	printf("%s\n",getIpAddress());
	printf("%s\n",getMacAddress());

    
	int request_result = sendArpRequest(sender_ip, target_ip, handle);
	
}




