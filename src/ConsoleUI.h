#pragma once

#include <string>

class ConsoleUI
{
public:
	ConsoleUI();
	~ConsoleUI();

	static void refresh_data();
	static void alarm_handler(int sig);

	static std::string format_packets(double packetsPerSecond);
	static std::string format_bandwidth(double bitsPerSecond);
	static std::string round_to_one_decimal(double number);
};

