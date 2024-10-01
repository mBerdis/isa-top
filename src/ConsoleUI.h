#pragma once

#include <string>

class ConsoleUI
{
public:
	ConsoleUI();
	~ConsoleUI();

	static void RefreshData(const char* row);
	static void alarm_handler(int sig);
};

