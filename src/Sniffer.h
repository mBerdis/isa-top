#pragma once
#include <pcap.h>

class Sniffer
{
public:
	Sniffer(char* interface, bool* err);
	~Sniffer();

	void start_capture();
	static void stop_capture();
	static int i;

private:
	static pcap_t* handle;

	int print_interfaces();
	static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
};
