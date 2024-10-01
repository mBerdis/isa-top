#include "Sniffer.h"
#include <iostream>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int Sniffer::i = 0;
pcap_t* Sniffer::handle = NULL;

Sniffer::Sniffer(char* interface, bool* err)
{
    i = 0;
    // If interface is not set, print available interfaces and exit
    if (interface == nullptr)
    {
        print_interfaces();
        *err = true;
        return;
    }

    // Open device in promiscuous mode
    char errBuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errBuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open device " << interface << ": " << errBuf << std::endl;
        *err = true;
    }


    // APPLYING FILTER
    //std::string filterExpression = options.create_filter();

    //// Compile the filter
    //struct bpf_program filter;
    //if (pcap_compile(handle, &filter, filterExpression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) 
    //{
    //    std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
    //    return 1;
    //}

    //// Apply filter
    //if (pcap_setfilter(handle, &filter) == -1) 
    //{
    //    std::cerr << "Error applying filter: " << pcap_geterr(handle) << std::endl;
    //    return 1;
    //}

    //// Free filter memory
    //pcap_freecode(&filter);
}

Sniffer::~Sniffer()
{
    // stop capture and close device
    pcap_breakloop(handle);
    pcap_close(handle);
}

void Sniffer::start_capture()
{
    pcap_loop(handle, 0, packet_handler, NULL);
}

void Sniffer::stop_capture()
{
    pcap_breakloop(handle);
}

int Sniffer::print_interfaces()
{
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;

    // Retrieve list of available network interfaces
    if (pcap_findalldevs(&interfaces, errBuf) == -1)
    {
        std::cerr << "Error finding devices: " << errBuf << std::endl;
        return 1;
    }

    // Print list of interfaces
    for (pcap_if_t* dev = interfaces; dev != nullptr; dev = dev->next)
    {
        std::cout << dev->name << std::endl;
    }

    // Free list
    pcap_freealldevs(interfaces);
    return 0;
}

void Sniffer::packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    i++;
    // Unused parameter to avoid compiler warnings
    (void)user;

    // Parse Ethernet header
    const struct ether_header* ethernet_header = (struct ether_header*)packet;


    // Print IP related things
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    {
        const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        char ipAddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), ipAddr, INET_ADDRSTRLEN);
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