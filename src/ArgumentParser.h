#pragma once

#include <iostream>
#include <getopt.h>
#include <string>

class ArgumentParser
{
public:
    ArgumentParser(int argc, char *argv[], bool* err);
    std::string create_filter();
    int get_packetCount();
    char* get_interface();
    bool get_sort_option();

private:
    char* interface;
    int packetCount, port, dstPort, srcPort;
    bool tcp, udp, icmp4, icmp6, arp, ndp, igmp, mld;
    std::string filter;

    bool sortByBytes;

    void add_port_filters();
    void end_block();
    void add_short_block(bool& hasPrevious, const std::string protocol);
    void add_new_block(bool& hasPrevious, const std::string protocol);
};