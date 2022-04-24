#include <iostream>
#include <pcap.h>
#include <string>
#include <regex>
#include <vector>
#include <sstream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
using namespace std;

// striktura pro uchování argumentů z argparse
struct settings {
    string interface;
    string port;
    int num = 1;
    vector<string> protocols; //protokoly pro tvoření filtru

};

int parseargs(int argc, char *argv[], settings &args){ // ukládá
    if(argc < 2){
       cout << "Usage: " << argv[0] << "[-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}" << endl;
       return 1;
    }
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0){
            if(i+1 >= argc ){
                return 0;
            }
            args.interface = argv[i+1];
            i++;
        }
        else if(strcmp(argv[i], "-p") == 0){
            if(i+1 >= argc){
             cerr << "Argument [port] passed without a value" << endl;
             return 1;
            }
            int number =atoi(argv[i+1]);
            if(number < 1 || number > 65535){
                cerr << "Invalid port number - must be in range between 1 and 65535";
                return 1;
            }
            args.port = argv[i+1];
            i++;
        }
        else if(strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0){
            args.protocols.push_back("proto \\tcp");
        }
        else if(strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0){
            args.protocols.push_back("proto \\udp");
        }
        else if(strcmp(argv[i], "--arp") == 0){
            args.protocols.push_back("arp");
        }
        else if( strcmp(argv[i], "--icmp") == 0){
            args.protocols.push_back("proto \\icmp");
        }
        else if(strcmp(argv[i], "-n") == 0){
              if(i+1 >= argc){
             cerr << "Argument [number] passed without a value" << endl;
             return 1;
            }
            args.num = atoi(argv[i+1]);
            i++;
        }
        else{
         cout << "Usage: " << argv[0] << "[-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}" << endl;
            return 1;
        }
    }
    return 0;
}
int findDevices(pcap_if_t *devices, char *errbuf){
    if (pcap_findalldevs(&devices, errbuf)) {
            cerr << errbuf << endl;
            return 1;
        }
    cout << "Available devices:" << endl;
    cout << "--------------------------" << endl;
    while (devices) {
        cout << devices->name << endl;
        devices = devices->next;
    }
    cout << "--------------------------" << endl;
    return 0;
}

int listDevices(settings *args){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if(!findDevices(alldevs, errbuf)){
        return 1;
    }else{
        cout << "specify interface" << endl;
        getline(cin, args->interface);
        return 0;
    }
}
//funkce pro vytvoření řetězce s filtry
string setFilters(settings *args){
    stringstream filter;
    if(args->port != ""){
        filter << "port " << args->port << " and ";
    }
    if (args->protocols.size() == 0){
        filter << "proto \\tcp" << " or " << "proto \\udp" << " or " << "proto \\icmp" << " or " << "arp" ;
        return filter.str();
    }
    filter << args->protocols[0];
    for(int i = 1; i < args->protocols.size(); i++){
        filter << " or " << args->protocols[i];
    }
    return filter.str();
}
/* Přejmuto z: https://stackoverflow.com/questions/3727421/expand-an-ipv6-address-so-i-can-print-it-to-stdout
   autor: nategoose
   funkce pro převod adresy formátu ipv6 na textový řetězec
    */
void ipv6_to_str_unexpanded(char *str, const struct in6_addr *addr) {
   sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                 (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                 (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                 (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                 (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                 (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                 (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                 (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}
/*Přejmuto z: https://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format
  Autor: Joe Hildebrand
  funkce pro převod času na požadovaný formát
 */
ssize_t getDateFromHeader(struct pcap_pkthdr *header, char* buffer, size_t size){
    struct tm *gm = gmtime(&header->ts.tv_sec);
    ssize_t written = -1;
    if (gm){
    written = (ssize_t)strftime(buffer, size, "%Y-%m-%dT%H:%M:%S", gm);
     if ((written > 0) && ((size_t)written < size))
    {
      int w = snprintf(buffer+written, size-(size_t)written, ".%06dZ", header->ts.tv_usec);
      written = (w > 0) ? written + w : -1;
    }
    }
    return written;
}
//callback funkce pro pcap_loop
void got_packet(u_char *args, struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *ethernet;
    ethernet = (struct ether_header *)packet;
    struct ip *ip;
    ushort ether_type = ntohs(ethernet->ether_type);

    char date[28];
    getDateFromHeader(header, date, sizeof(date));

    struct ether_addr src;
    memcpy(&src, ethernet->ether_shost, sizeof(src));
    struct ether_addr dest; 
    memcpy(&dest, ethernet->ether_shost, sizeof(dest));
    

    cout << "timestamp: " << date << endl;
    cout << "src MAC: " << ether_ntoa(&src) << endl;
    cout << "dst MAC: " << ether_ntoa(&dest) << endl;
    cout << "frame length: " << header->len << " bytes" << endl;

    if(ether_type == ETHERTYPE_IP){ // IPV4
        ip = (struct ip *)(packet + sizeof(struct ether_header));
        cout << "src IP: " << inet_ntoa(ip->ip_src) << endl;
        cout << "dst IP: " << inet_ntoa(ip->ip_dst) << endl;
    }
    else if(ether_type == ETHERTYPE_IPV6){ // IPV6
        struct ip6_hdr *ipv6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        char address[40];
        ipv6_to_str_unexpanded(address,&ipv6->ip6_src);
        cout << "src IP: " << address << endl;
        ipv6_to_str_unexpanded(address,&ipv6->ip6_dst);
        cout << "dst IP: " << address << endl;
        ip->ip_p = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    }
    else if(ether_type == ETHERTYPE_ARP){ // ARP - žádné dodatečné informace
        return;
    }
    else{
        cerr << "Unsupported ethernet type" << endl;
        return;
    }

    
    int offset = sizeof(struct ip) + sizeof(struct ether_header);
    if(ip->ip_p == IPPROTO_TCP){ // TCP Protokol
            struct tcphdr *tcp = (struct tcphdr *)(packet + offset);
            cout << "src port: " << ntohs(tcp->th_sport) << endl;
            cout << "dst port: " << ntohs(tcp->th_dport) << endl;
            cout << endl;
            offset+=sizeof(struct tcphdr);
        }
        else if(ip->ip_p == IPPROTO_UDP){ //UDP Protokol
            struct udphdr *udp = (struct udphdr *)(packet + offset);
            cout << "src port: " << ntohs(udp->uh_sport) << endl;
            cout << "dst port: " << ntohs(udp->uh_dport) << endl;
            cout << endl;
            offset+=sizeof(struct udphdr); 
        }
        else if(ip->ip_p == IPPROTO_ICMP){ //ICMP Protokol
            struct icmphdr *icmp = (struct icmphdr *)(packet + offset);
            cout << "ICMP type: " << ntohs(icmp->type) << endl;
            cout << "ICMP code: " << ntohs(icmp->code) << endl;
            cout << endl;
            offset+=sizeof(struct icmphdr);
        }
        else{
            cout << "Unsuported protocol" << endl;
            return;
        }
    const unsigned int data_len = header->len - offset;
    u_char *payload =(u_char *)packet + offset;
    if(data_len == 0){
        cout << endl;
        return;
    }
    for(int i=0; i < data_len; i+=16){
        printf("0x%04x:", i);
        for (int y=0; y < 16; y++){
            if (i+y < data_len){
               printf("  %02x", payload[i+y]); 
            }else if(data_len > 16){
                printf("    ");
            }else{
                break;
            }
        }
        printf("  ");
        for (int y=0; y < 16; y++){
            if (i+y >= data_len){
                break;
            }
        printf(" %c", isprint(payload[i+y]) ? payload[i+y] : '.');
        }
        printf("\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{   
    settings args;
    if(parseargs(argc, argv, args)){
        return 1;
    }
    if (args.interface.size() == 0) {
        if(!listDevices(&args)){
            return 2;
        }
        if(args.interface.size() > 0){
            cout << "Using interface: " << args.interface << endl;
        }else{
            cout << "interface not specified" << endl;
            return 1;
        }
    }

   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if(!handle){
        cout << "Couldn't open device " << args.interface << ": " << errbuf << endl;
        return 3;
    }

    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_lookupnet(args.interface.c_str(), &net, &mask, errbuf);

    if (pcap_datalink(handle) != DLT_EN10MB && pcap_datalink(handle) != DLT_LINUX_SLL) {
        cerr << "Unsupported interface" << endl;
        return 4;
    }
    if (pcap_lookupnet(args.interface.c_str(), &net, &mask, errbuf) == -1) {
        std::cerr << "Couldn't load netmask: "<< errbuf << std::endl;
        return 5;
    }

    string filters = setFilters(&args);
    if(pcap_compile(handle, &fp, filters.c_str() , 0, net) == -1){
        cout << "Couldn't parse filter " << args.port << ": " << pcap_geterr(handle) << endl;
        return 1;
    }
    if(pcap_setfilter(handle, &fp) == -1){
        cout << "Couldn't install filter " << args.port << ": " << pcap_geterr(handle) << endl;
        return 1;
    }

    if(pcap_loop(handle, args.num, (pcap_handler)&got_packet, NULL) < 0){
      cout << "Pcap failed" << endl;
    }
    pcap_close(handle);
    return 0;
}
//code packet sniffer using pcap library
//https://www.tcpdump.org/pcap.html
//https://www.tcpdump.org/manpages/pcap.7.html
//https://www.tcpdump.org/manpages/pcap-savefile.7.html
//https://www.tcpdump.org/manpages/pcap-tstamp.7.html
//https://www.tcpdump.org/manpages/pcap-lookupnet.7.html
//make packet sniffer using pcap library