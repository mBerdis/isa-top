#include "ArgumentParser.h"

ArgumentParser::ArgumentParser(int argc, char *argv[], bool* err)
    : interface(nullptr), packetCount(1), port(-1),
      dstPort(-1), srcPort(-1), tcp(false), udp(false), 
      icmp4(false), icmp6(false), arp(false),
      ndp(false), igmp(false), mld(false), filter(""),
      sortByBytes(false), sortByPackets(false)
{
    int opt;

    // Define long options
    static struct option longOptions[] = {
        {"interface", required_argument, nullptr, 'i'},
        {"sort", required_argument, nullptr, 's'},
        {nullptr, 0, nullptr, 0}
    };

    // Parse command-line arguments
    while ((opt = getopt_long(argc, argv, "i:s:", longOptions, nullptr)) != -1) 
    {
        switch (opt) 
        {
            case 'i': 
            {
                if (optarg == NULL && optind < argc && argv[optind][0] != '-')
                    optarg = argv[optind++];
                if (optarg != NULL)
                    interface = optarg;
                break;
            }
            case 's':
            {
                sortByBytes     = optarg[0] == 'b' ? true : false;
                sortByPackets   = optarg[0] == 'p' ? true : false;

                // check if atleast one is true, if not wrong argument
                if (!sortByBytes && !sortByPackets)
                {
                    std::cerr << "Usage: " << argv[0] << " [options]\n";
                    *err = true;
                    return;
                }

                break;
            }

            default:
                std::cerr << "Usage: " << argv[0] << " [options]\n";
                *err = true;
                return;
        }
    }

    *err = false;
    return;
}

std::string ArgumentParser::create_filter()
{
    filter = "";    // in-case someone calls this function multiple times.
    bool hasPrevious = false;

    if (tcp)
    {
        add_new_block(hasPrevious, "tcp ");
        add_port_filters();
        end_block();
    }

    if (udp)
    {
        add_new_block(hasPrevious, "udp ");
        add_port_filters();
        end_block();
    }

    if (icmp4) add_short_block(hasPrevious, "icmp");
    if (icmp6) add_short_block(hasPrevious, "icmp6");
    if (arp)   add_short_block(hasPrevious, "arp");
    if (igmp)  add_short_block(hasPrevious, "igmp");
    if (ndp)   
        add_short_block(hasPrevious, "(icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137)");
    if (mld)   
        add_short_block(hasPrevious, "(icmp6[icmp6type] == 143 or (icmp6[icmp6type] >= 130 and icmp6[icmp6type] <= 132))");

    return filter;
}

int ArgumentParser::get_packetCount()
{
    return packetCount;
}

char *ArgumentParser::get_interface()
{
    return interface;
}

void ArgumentParser::add_port_filters()
{
    bool hasPrevious = false;

    if (port != -1)
    {
        if (hasPrevious) filter += " or ";
        filter += "port " + std::to_string(port);
        hasPrevious = true;
    }
        
    if (dstPort != -1) 
    {
        if (hasPrevious) filter += " or ";
        filter += "dst port " + std::to_string(dstPort);
        hasPrevious = true;
    }
    if (srcPort != -1)
    {
        if (hasPrevious) filter += " or ";
        filter += "src port " + std::to_string(srcPort);
        hasPrevious = true;
    }
}

void ArgumentParser::add_new_block(bool& hasPrevious, const std::string protocol)
{
    if (hasPrevious) filter += " or ";
    else hasPrevious = true;

    filter += "(" + protocol;
}

void ArgumentParser::add_short_block(bool& hasPrevious, const std::string protocol)
{
    if (hasPrevious) filter += " or ";
    else hasPrevious = true;

    filter += protocol;
}

void ArgumentParser::end_block()
{
    filter += ")";
}
