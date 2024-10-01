#include "Sniffer.h"
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


pcap_t* Sniffer::handle = NULL;
std::unordered_map<std::string, ConnectionInfo> Sniffer::networkCommunications;

Sniffer::Sniffer(char* interface, bool* err)
{
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

    networkCommunications.clear();
    networkCommunications.reserve(10);

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

void Sniffer::extract_address(ConnectionInfo& connection, const ip* ipv4)
{
    char temp[INET_ADDRSTRLEN];

    // Extract sender IP
    inet_ntop(AF_INET, &(ipv4->ip_src), temp, INET_ADDRSTRLEN);
    connection.senderIP = std::string(temp);

    // Extract reciever IP
    inet_ntop(AF_INET, &(ipv4->ip_dst), temp, INET_ADDRSTRLEN);
    connection.receiverIP = std::string(temp);
}

void Sniffer::extract_address(ConnectionInfo& connection, const ip6_hdr* ipv6)
{
    char temp[INET6_ADDRSTRLEN];

    // Extract sender IP
    inet_ntop(AF_INET6, &(ipv6->ip6_src), temp, INET6_ADDRSTRLEN);
    connection.senderIP = std::string(temp);

    // Extract reciever IP
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), temp, INET6_ADDRSTRLEN);
    connection.receiverIP = std::string(temp);
}

void Sniffer::extract_protocol(ConnectionInfo& connection, const uint8_t protocol, const unsigned int headerOffset, const u_char* packet)
{
    if (protocol == IPPROTO_TCP)
    {
        // Parse TCP header
        const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + headerOffset);
        connection.senderPort   = tcpHeader->th_sport;
        connection.receiverPort = tcpHeader->th_dport;
        connection.protocol     = "TCP";
    }
    else if (protocol == IPPROTO_UDP)
    {
        // Parse UDP header
        const struct udphdr* udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + headerOffset);
        connection.senderPort   = udpHeader->uh_sport;
        connection.receiverPort = udpHeader->uh_dport;
        connection.protocol     = "UDP";
    }
    else 
    {
        connection.protocol = "UDP";
    }
}

void Sniffer::packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    // Unused parameter to avoid compiler warnings
    (void)user;

    // Parse Ethernet header
    const struct ether_header* ethernetHeader = (struct ether_header*)packet;

    ConnectionInfo connection;

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
    {
        const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        extract_address(connection, ipHeader);
        
        const unsigned int protHeaderOffset = ipHeader->ip_hl * 4;
        extract_protocol(connection, ipHeader->ip_p, protHeaderOffset, packet);

    }
    else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6)
    {
        const struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        extract_address(connection, ipv6Header);

        const unsigned int protHeaderOffset = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen;
        extract_protocol(connection, ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt, protHeaderOffset, packet);
    }

    std::string key = generate_key(connection);

    // Search for the connection key in the map
    auto it = networkCommunications.find(key);

    if (it != networkCommunications.end()) 
    {
        // If the key is found, update the existing connection info
        it->second.totalBytes += header->len;  // Increment total received bytes
        it->second.packetCount += 1;
    }
    else {
        // If the key is not found, create a new ConnectionInfo and insert it
        connection.totalBytes  = header->len;
        connection.packetCount = 1;

        // Add the new connection to the map
        networkCommunications[key] = connection;
    }

    //// Print ethernet header related things
    //print_time("timestamp: ", header->ts);
}

std::string Sniffer::generate_key(const ConnectionInfo& connection)
{
    return  connection.senderIP + ":" + std::to_string(connection.senderPort) 
            + " -> " +
            connection.receiverIP + ":" + std::to_string(connection.receiverPort) 
            + " (" +
            connection.protocol + ")";
}

void Sniffer::clear_communications()
{
    networkCommunications.clear();
}

const std::unordered_map<std::string, ConnectionInfo>& Sniffer::get_communications()
{
    return networkCommunications;
}
