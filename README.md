# IPK24_NetworkSniffer
Author: Maroš Berdis (xberdi01) \
Date: 22.04.2024 \
License: GNU GENERAL PUBLIC LICENSE Version 3 \
[Assignment specification](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%202/zeta)

Network sniffer application written in ***C++*** based on ***pcap*** library[[2]](#sources).

## Table of Contents

- [IPK24_NetworkSniffer](#ipk24_networksniffer)
    - [Table of Contents](#table-of-contents)
    - [Build & Run](#build--run)
    - [Problematique](#problematique)
        - [Headers](#headers)
    - [Implementation](#implementation)
        - [1. Argument Parsing](#1-argument-parsing)
        - [2. Handling Interrupt Signal](#2-handling-interrupt-signal)
        - [3. Packet Dissection](#3-packet-dissection)
    - [Testing](#testing)
        - [Testing UDP/TCP](#testing-udptcp)
        - [Testing ICMP](#testing-icmp)
        - [Testing ARP](#testing-arp)
    - [Sources](#sources)

## Build & Run
Project uses ***Makefile*** to handle build. Available commands:
|Command             |Description           |
| ---                | -----------          |
|`make`              | creates ***ipk-sniffer*** executable in project directory |
|`make clean`        | cleans build-generated files |
|`make run`          | builds and runs the app on eth0 interface |

The program ***ipk-sniffer*** accepts following CLI arguments:
|Argument                   | Description |
| ---                       | ----------- |
|`-n`                       | How many packets to capture. ***Default value: 1.***  |
|`-i VAL`, `--interface VAL`        | Specifies interface to sniff on. If no value given, program prints a list of available interfaces.  |
|`-t`, `--tcp`              | Will display only TCP packets |
|`-u`, `--udp`              | Will display only UDP packets |
| `-p PORT`, `--port PORT`  | Filter TCP/UDP based on port number. Completes ***TCP*** or ***UDP*** filter. |
| `--port-destination PORT` | Filter TCP/UDP based on destination port number. Completes ***TCP*** or ***UDP*** filter.|
| `--port-source PORT`      | Filter TCP/UDP based on source port number. Completes ***TCP*** or ***UDP*** filter. |
| `--icmp4`                 | Display only ICMPv4 packets.                                        |
| `--icmp6`                 | Display only ICMPv6 echo request/response packets.                  |
| `--arp`                   | Display only ARP frames.                                            |
| `--ndp`                   | Display only NDP packets (subset of ICMPv6).                        |
| `--igmp`                  | Display only IGMP packets.                                          |
| `--mld`                   | Display only MLD packets (subset of ICMPv6).                        |

<span style="color:orange">***Warning!*** You need to have sufficient privileges to open interfaces for capturing. </span>

Program exit codes:
|Exit code | Description |
| ---      | ----------- |
|`0`       | Success |
|`1`       | Error |

## Problematique
Network packet capture is a necessary part of analyzing targeted network, whether its with debugging or malicious intend. It helps us understand incoming and outgoing traffic on network interface that we are listening on.

The program starts packet capture by opening a network interface in promiscuous mode, allowing it to capture all packets traversing the network, regardless of their intended destination. Applying a filter can limit the number of captured packets, thereby improving performance.

Captured packets are dissected into headers and payload to obtain meaningful information from them.

### Headers
Overview of headers and which parts of them program uses:
- ***Ethernet Header*** 
    - program prints Source and Destination MAC addresses.
- ***IPv4 Header*** [[RFC 791]](#sources)
    ```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ```
    - program prints Source and Destination addresses.

- ***IPv6 Header*** [[RFC 8200]](#sources)
    ```
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version| Traffic Class |           Flow Label                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Payload Length        |  Next Header  |   Hop Limit   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                         Source Address                        +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                      Destination Address                      +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ```
    - program prints Source and Destination 128-bit addresses in recommended text format [[RFC 5952]](#sources).

- ***TCP Header*** [[RFC 9293]](#sources)
    ```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |       |C|E|U|A|P|R|S|F|                               |
    | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
    |       |       |R|E|G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           [Options]                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               :
    :                             Data                              :
    :                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ```
    - program prints Source and Destination ports.

- ***UDP Header*** [[RFC 768](#sources)]
    ```
    0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |
    |          data octets ...
    +---------------- ...
    ```
    - program prints Source and Destination ports.

## Implementation
The `ipk-sniffer` program serves as a wrapper around the ***pcap*** library[[2]](#sources), providing a user-friendly interface for capturing and analyzing network packets. Overview of its implementation:

### 1. Argument Parsing
Command line arguments are parsed into program settings which are later processed into filter string. Class `ArgumentParser` handles this responsibility. Filter string consists of blocks that are separated by the logical OR (`or`) operator. Filter string format complies with ***pcap-filter*** syntax [[3]](#sources). Example of how CLI arguments are parsed into filter string:
```
./ipk-sniffer -i eth0 -t --arp --port 22 --port-destination 443 --icmp4
Filter: "(tcp port 22 or dst port 443) or icmp or arp"
```

This filter string is then compiled and applied: 
```cpp
std::string filterExpression = options.create_filter();

// Compile the filter
struct bpf_program filter;
if (pcap_compile(handle, &filter, filterExpression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) 
{
    std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
    return 1;
}

// Apply filter
if (pcap_setfilter(handle, &filter) == -1) 
{
    std::cerr << "Error applying filter: " << pcap_geterr(handle) << std::endl;
    return 1;
}
```

### 2. Handling Interrupt Signal
Program can be terminated at any moment by receiving `CTRL + C` sequence. This is simply achieved by registering signal handler which calls `pcap_breakloop()`.

```cpp
// Function to handle interrupt signal
void signal_handler(int signum) 
{
    pcap_breakloop(handle);
}

int main(int argc, char *argv[])
{
    // Register signal handler for interrupt signal (Ctrl+C)
    signal(SIGINT, signal_handler);
    // ...
}
```

### 3. Packet Dissection
Program provides `packet_handler()` function to the ***pcap*** library. This function is called ***for each packet*** that has been captured and meets the specified filter. It's purpose is to dissect received packet and print its content to the standard output (`stdout`). Simplified version of this function:
```cpp
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) 
{
    // Print ethernet header related things
    const struct ether_header* ethernet_header = (struct ether_header*)packet;
    print_time("timestamp: ", header->ts);
    print_mac_addr("src MAC: ", ethernet_header->ether_shost);
    print_mac_addr("dst MAC: ", ethernet_header->ether_dhost);
    std::cout << "frame length: " << header->len << " bytes" << std::endl;

    // Print IP related things
    const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    print_ip_addr("src IP: ", &(ip_header->ip_src));
    print_ip_addr("dst IP: ", &(ip_header->ip_dst));
    print_ports(ip_header->ip_p, ip_header->ip_hl * 4, packet);

    print_data(header->caplen, packet);
}
```

## Testing
### Testing UDP/TCP
- by sending a single packet and comparing ***Wireshark***'s and ***ipk-sniffer***'s output.
    ```
     echo "Hello UDP world" | nc -u -w1 172.23.0.1 4567
    ```
    ![Udp capture](images/udp_capture.png)

### Testing ICMP
- manually by utilizing ***ping*** program.
    ```
    anon@DESKTOP:~$ ping google.com -c 1
    PING google.com (142.251.36.110) 56(84) bytes of data.
    64 bytes from prg03s11-in-f14.1e100.net (142.251.36.110): icmp_seq=1 ttl=118 time=96.8 ms

    --- google.com ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 96.837/96.837/96.837/0.000 ms
    ```
    ```
    anon@DESKTOP:~$ sudo ./ipk-sniffer -i eth0 -n 1 --icmp4
    timestamp: 2024-04-12T22:15:58.942+02:00
    src MAC: 00:15:5d:3c:4a:d8
    dst MAC: 00:15:5d:08:c4:88
    frame length: 98 bytes
    src IP: 172.23.14.203
    dst IP: 142.251.36.110

    0x0000: 00 15 5d 08 c4 88 00 15 5d 3c 4a d8 08 00 45 00 ..]..... ]<J...E.
    0x0010: 00 54 94 68 40 00 40 01 37 f5 ac 17 0e cb 8e fb .T.h@.@. 7.......
    0x0020: 24 6e 08 00 d2 ca 00 05 00 01 7e 96 19 66 00 00 $n...... ..~..f..
    0x0030: 00 00 c0 5f 0e 00 00 00 00 00 10 11 12 13 14 15 ..._.... ........
    0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 ........ .. !"#$%
    0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 &'()*+,- ./012345
    0x0060: 36 37                                           67
    ```

### Testing ARP
- manually by utilizing ***arping*** program.
    ```
    anon@DESKTOP:~$ sudo arping 192.0.2.2 -i eth0 -c 1
    ARPING 192.0.2.2
    Timeout

    --- 192.0.2.2 statistics ---
    1 packets transmitted, 0 packets received, 100% unanswered (0 extra)
    ```
    ```
    anon@DESKTOP:~$ sudo ./ipk-sniffer -i eth0 -n 1 --arp
    timestamp: 2024-04-12T22:03:06.923+02:00
    src MAC: 00:15:5d:3c:4a:d8
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 58 bytes

    0x0000: ff ff ff ff ff ff 00 15 5d 3c 4a d8 08 06 00 01 ........ ]<J.....
    0x0010: 08 00 06 04 00 01 00 15 5d 3c 4a d8 ac 17 0e cb ........ ]<J.....
    0x0020: 00 00 00 00 00 00 c0 00 02 02 00 00 00 00 00 00 ........ ........
    0x0030: 00 00 00 00 00 00 00 00 00 00                   ........ ..
    ```

## Sources
- [1] [Assignment specification](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%202/zeta)
- [2] [PCAP library](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [3] [PCAP-FILTER syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)

- [RFC 791] Internet Protocol. [online]. [cited 2024-04-22]. Sep 1981, doi:10.17487/RFC0791. Available at: https://datatracker.ietf.org/doc/html/rfc791

- [RFC 9293] Eddy, W.: Transmission Control Protocol (TCP). [online]. [cited 2024-04-22]. Aug 2022, doi:10.17487/RFC9293.
Available at: https://datatracker.ietf.org/doc/html/rfc9293

- [RFC 768] User Datagram Protocol. [online]. [cited 2024-04-22]. Aug 1980, doi:10.17487/RFC0768. Available at: https://datatracker.ietf.org/doc/html/rfc768

- [RFC 8200] Deering, D. S. E.; Hinden, B.: Internet Protocol, Version 6 (IPv6) Specification. [online]. [cited 2024-04-22]. Jul 2017,
doi:10.17487/RFC8200. Available at: https://datatracker.ietf.org/doc/html/rfc8200

- [RFC 5952] Kawamura, S.; Kawashima, M.: A Recommendation for IPv6 Address Text Representation. [online]. [cited 2024-04-22]. Aug 2010, doi:10.17487/RFC5952. Available at: https://datatracker.ietf.org/doc/html/rfc5952

- [RFC 3339] Newman, C.; Klyne, G.: Date and Time on the Internet: Timestamps. Jul 2002, doi: 10.17487/RFC3339. Available at: https://datatracker.ietf.org/doc/html/rfc3339