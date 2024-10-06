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
#include "Sniffer.h"

#define MAC_ADDR_LENGHT 18

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

// Function to handle interrupt signal
void signal_handler(int signum) 
{
    Sniffer::stop_capture();
}
    
int main(int argc, char *argv[]) 
{
    // Register signal handler for interrupt signal (Ctrl+C)
    signal(SIGINT, signal_handler);

    // helper variable to check if err occured in object constructors
    bool err = false;

    // Parse CLI arguments
    ArgumentParser options(argc, argv, &err);
    if (err == true)
        return 1;

    // Create sniffer
    Sniffer PacketSniffer(options.get_interface(), &err);
    if (err == true)
        return 1;

    // Create GUI
    ConsoleUI myGUI(options.get_sort_option());

    PacketSniffer.start_capture();

    return 0;
}
