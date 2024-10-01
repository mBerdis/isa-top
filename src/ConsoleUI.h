#pragma once

#include <string>

class ConsoleUI
{
public:
	ConsoleUI();
	~ConsoleUI();

	static void RefreshData();
	static void alarm_handler(int sig);
};

