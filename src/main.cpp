#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <csignal>
#include <signal.h>
#include <iomanip>
#include "ArgumentParser.h"
#include "ConsoleUI.h"

#define MAC_ADDR_LENGHT 18

// this needs to be global for signal_handler() able to stop pcap loop
pcap_t* handle;
//ConsoleUI myUI;

void print_mac_addr(const std::string desc, const uint8_t* addrPtr)
{
    char macAddr[MAC_ADDR_LENGHT];
    sprintf(macAddr, "%02x:%02x:%02x:%02x:%02x:%02x",
        addrPtr[0],
        addrPtr[1],
        addrPtr[2],
        addrPtr[3],
        addrPtr[4],
        addrPtr[5]);

    std::cout << desc << macAddr << std::endl;
}

void print_ip_addr(const std::string desc, const in_addr* addrPtr)
{
    char ipAddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addrPtr, ipAddr, INET_ADDRSTRLEN);
    std::cout << desc << ipAddr << std::endl;
}

void print_ipv6_addr(const std::string desc, const in6_addr* addrPtr)
{
    // Convert IPv6 address to a string in canonical form
    char ipv6_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addrPtr, ipv6_str, sizeof(ipv6_str));

    // Print prefix and formatted IPv6 address
    std::cout << desc << ipv6_str << std::endl;
}

void print_time(const std::string desc, const timeval& ts)
{
    char time[64];
    struct tm *localTime = localtime(&ts.tv_sec);
    strftime(time, sizeof(time), "%Y-%m-%dT%H:%M:%S", localTime);

    // Calculate the timezone offset
    int timezoneOffset = localTime->tm_gmtoff / 3600;
    int timezoneOffsetMinute = (localTime->tm_gmtoff % 3600) / 60;

    // Print the timestamp in RFC 3339 format
    std::cout << desc << time << "." << std::setw(3) << std::setfill('0') << (ts.tv_usec / 1000);

    // Print the timezone offset
    if (timezoneOffset >= 0) {
        std::cout << "+";
    } else {
        std::cout << "-";
        timezoneOffset = -timezoneOffset;
    }
    std::cout << std::setw(2) << std::setfill('0') << timezoneOffset << ":" << std::setw(2) << std::setfill('0') << timezoneOffsetMinute << std::endl;
}

void print_port(const std::string desc, uint16_t port) 
{
    std::cout << desc << ntohs(port) << std::endl;
}

void print_ports(uint8_t protocol, unsigned int headerOffset, const u_char* packet)
{
    // Check if the packet is TCP
    if (protocol == IPPROTO_TCP) 
    {
        // Parse TCP header
        const struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + headerOffset);
        print_port("src port: ", tcp_header->th_sport);
        print_port("dst port: ", tcp_header->th_dport);
    } 
    else if (protocol == IPPROTO_UDP) 
    {
        // Parse UDP header
        const struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + headerOffset);
        print_port("src port: ", udp_header->uh_sport);
        print_port("dst port: ", udp_header->uh_dport);
    }
}

void print_data(bpf_u_int32 len, const u_char* packet)
{
    std::cout << std::endl;

    for (size_t row = 0; row < len; row += 16)
    {
        std::cout << "0x" << std::setw(4) << std::setfill('0') << std::hex << static_cast<int>(row) << ":" << std::dec;

        // Print data in hex format
        for (size_t i = row; i < (row + 16) && i < len; i++) {
            std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[i]) << std::dec;
        }

        // Check if fill is needed to properly align second ascii part
        int rowFill = len - row;
        if (rowFill < 16)
        {
            std::cout << std::setw((16 - rowFill) * 3 + 1) << std::setfill(' ');
        }

        // Print data in ascii format
        for (size_t i = row; i < (row + 16) && i < len; i++) 
        {
            if (i % 8 == 0)
                std::cout << " ";

            if (isprint(packet[i])) 
                std::cout << packet[i];
            else 
                std::cout << ".";
        }
        
        std::cout << std::endl;
    }
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) 
{
    // Unused parameter to avoid compiler warnings
    (void)user;

    // Parse Ethernet header
    const struct ether_header* ethernet_header = (struct ether_header*)packet;


    // Print IP related things
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) 
    {
        const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        char ipAddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&(ip_header->ip_src), ipAddr, INET_ADDRSTRLEN);
        //myUI.RefreshData(ipAddr);
    }

    //// Print ethernet header related things
    //print_time("timestamp: ", header->ts);
    ////print_mac_addr("src MAC: ", ethernet_header->ether_shost);
    ////print_mac_addr("dst MAC: ", ethernet_header->ether_dhost);
    //std::cout << "frame length: " << header->len << " bytes" << std::endl;

    ////std::map<std::string, int>

    //// Print IP related things
    //if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) 
    //{
    //    const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    //    print_ip_addr("src IP: ", &(ip_header->ip_src));
    //    print_ip_addr("dst IP: ", &(ip_header->ip_dst));
    //    print_ports(ip_header->ip_p, ip_header->ip_hl * 4, packet);
    //}
    //else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) 
    //{
    //    const struct ip6_hdr* ipv6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
    //    print_ipv6_addr("src IP: ", &(ipv6_header->ip6_src));
    //    print_ipv6_addr("dst IP: ", &(ipv6_header->ip6_dst));
    //    print_ports(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt, (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen), packet);
    //}

    ////print_data(header->caplen, packet);
    //std::cout << std::endl;
}

// Function to handle interrupt signal
void signal_handler(int signum) 
{
    pcap_breakloop(handle); // stop capturing packets when got interrupt signal
}

int print_interfaces(char* errBuf)
{
    pcap_if_t *interfaces;

    // Retrieve list of available network interfaces
    if (pcap_findalldevs(&interfaces, errBuf) == -1) 
    {
        std::cerr << "Error finding devices: " << errBuf << std::endl;
        return 1;
    }

    // Print list of interfaces
    for (pcap_if_t *dev = interfaces; dev != nullptr; dev = dev->next) 
    {
        std::cout << dev->name << std::endl;
    }

    // Free list
    pcap_freealldevs(interfaces);
    return 0;
}
    
int main(int argc, char *argv[]) 
{
    std::cerr << "Here" << std::endl << std::flush;

    std::cout << "WEWEW" << std::endl << std::flush;
    return 10;


    //// Register signal handler for interrupt signal (Ctrl+C)
    //signal(SIGINT, signal_handler);

    //// Parse CLI arguments
    //bool err;
    //ArgumentParser options(argc, argv, &err);
    //if (err == true)
    //{
    //    std::cerr << "Error parsing arguments." << std::endl;
    //    return 1;
    //}

    //char errBuf[PCAP_ERRBUF_SIZE];

    //// If interface is not set, print available interfaces and exit
    //if (options.get_interface() == nullptr)
    //    return print_interfaces(errBuf);

    //// Open device in promiscuous mode
    //handle = pcap_open_live(options.get_interface(), BUFSIZ, 1, 1000, errBuf);
    //if (handle == NULL) {
    //    std::cerr << "Couldn't open device " << options.get_interface() << ": " << errBuf << std::endl;
    //    return 1;
    //}

    //// APPLYING FILTER
    ////std::string filterExpression = options.create_filter();

    ////// Compile the filter
    ////struct bpf_program filter;
    ////if (pcap_compile(handle, &filter, filterExpression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) 
    ////{
    ////    std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
    ////    return 1;
    ////}

    ////// Apply filter
    ////if (pcap_setfilter(handle, &filter) == -1) 
    ////{
    ////    std::cerr << "Error applying filter: " << pcap_geterr(handle) << std::endl;
    ////    return 1;
    ////}

    ////// Free filter memory
    ////pcap_freecode(&filter);

    //myUI.RefreshData("");

    //// Start packet capture
    //pcap_loop(handle, -1, packet_handler, NULL);

    //// Close device when done capturing
    //pcap_close(handle);

    return 0;
}
