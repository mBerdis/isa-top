/*****************************************************************//**
 * \file   Sniffer.h
 * \author Maroš Berdis (xberdi01)
 *********************************************************************/

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

	// Tx
	double transmittedBytes;
	double transmittedPackets;

	// Rx
	double recievedBytes;
	double recievedPackets;

	ConnectionInfo() : 
		senderIP{ NULL }, senderPort{ 0 }, 
		receiverIP{ NULL }, receiverPort{ 0 }, 
		protocol{ NULL }, 
		transmittedBytes{ 0 }, transmittedPackets{ 0 },
		recievedBytes{ 0 }, recievedPackets{ 0 }
	{}
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

	// generates key for accessing communications map
	static std::string generate_key(const ConnectionInfo& connection);

	// generate_key() but switches sender and reciever to check if this packet is a response
	static std::string generate_alternate_key(const ConnectionInfo& connection);
};
