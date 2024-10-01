#pragma once
#include <pcap.h>
#include <unordered_map>
#include <iostream>

struct ConnectionInfo
{
	std::string senderIP;     // Source IP address
	int senderPort;           // Source port number

	std::string receiverIP;   // Destination IP address
	int receiverPort;         // Destination port number

	std::string protocol;     // Protocol
	size_t totalBytes;        // Total bytes transferred in this connection
	size_t packetCount;		  // Total packets transferred in this connection

	ConnectionInfo(std::string s_ip, int s_port, std::string r_ip, int r_port, std::string prot) :
		senderIP{ s_ip }, senderPort{ s_port },
		receiverIP{ r_ip }, receiverPort{ r_port },
		protocol{ prot }, totalBytes{ 0 }, packetCount{ 0 } {}

	ConnectionInfo() : 
		senderIP{ NULL }, senderPort{ 0 }, 
		receiverIP{ NULL }, receiverPort{ 0 }, 
		protocol{ NULL }, totalBytes{ 0 }, packetCount{ 0 } {}
};


class Sniffer
{
public:
	Sniffer(char* interface, bool* err);
	~Sniffer();

	void start_capture();
	static void stop_capture();

	static void clear_communications();
	static const std::unordered_map<std::string, ConnectionInfo>& get_communications();

private:
	static pcap_t* handle;
	static std::unordered_map<std::string, ConnectionInfo> networkCommunications;

	int print_interfaces();

	// needs to be static for pcap
	static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

	// needs to be static because its called from packet_handler
	static void extract_address(ConnectionInfo& connection, const struct ip* ipv4);
	static void extract_address(ConnectionInfo& connection, const struct ip6_hdr* ipv6);
	static void extract_protocol(ConnectionInfo& connection, const uint8_t protocol, const unsigned int headerOffset, const u_char* packet);
	static std::string generate_key(const ConnectionInfo& connection);
};
