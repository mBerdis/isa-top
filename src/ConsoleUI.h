/*****************************************************************//**
 * \file   ConsoleUI.h
 * \author Maroš Berdis (xberdi01)
 *********************************************************************/

#pragma once

#include <string>
#include "Sniffer.h"

class ConsoleUI
{
public:
	ConsoleUI(bool sortByBytes);
	~ConsoleUI();

	static bool sortBytes;

	static void refresh_data();
	static void alarm_handler(int sig);

private:
	static bool sort_by_bytes(const std::pair<std::string, ConnectionInfo>& a, const std::pair<std::string, ConnectionInfo>& b);
	static bool sort_by_packets(const std::pair<std::string, ConnectionInfo>& a, const std::pair<std::string, ConnectionInfo>& b);

	static std::string format_packets(double packetsPerSecond);
	static std::string format_bandwidth(double bitsPerSecond);
	static std::string round_to_one_decimal(double number);
};

