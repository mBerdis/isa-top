#include "ConsoleUI.h"
//#include <ncurses.h>
#include <curses.h>
#include <string>
#include <vector>
#include <iostream>
#include <signal.h>
#include "Sniffer.h"
#include <iomanip>
#include <sstream>

ConsoleUI::ConsoleUI()
{
    initscr();            // Initialize ncurses
    cbreak();             // Disable line buffering, but still allow Ctrl+C
    noecho();             // Don't echo input to the terminal
    keypad(stdscr, FALSE); // Disable special input handling like arrow keys
    timeout(-1);          // Don't wait for user input (disable input completely)

    signal(SIGALRM, alarm_handler);

    // Refresh the screen to show changes
    refresh_data();
}

ConsoleUI::~ConsoleUI()
{
    // deallocates memory and ends ncurses
    endwin();
}

void ConsoleUI::refresh_data()
{
    alarm(1);   // set alarm for 1 sec

    // Clear the screen before printing
    clear();

    // Print header
    mvaddstr(0, 0, "SRC IP: PORT");
    mvaddstr(0, COLS / 2 - 20, "DST IP: PORT");
    mvaddstr(0, COLS - 50, "PROTO");
    mvaddstr(0, COLS - 35, "Rx");
    mvaddstr(0, COLS - 15, "Tx");

    mvaddstr(1, COLS - 40, "b/s");
    mvaddstr(1, COLS - 30, "p/s");

    mvaddstr(1, COLS - 20, "b/s");
    mvaddstr(1, COLS - 10, "p/s");

    // Start printing from the third row
    int row = 2;

    // Iterate through the map
    for (const auto& entry : Sniffer::get_communications())
    {
        const ConnectionInfo& connection = entry.second;

        // Format the data as strings
        std::string src      = connection.senderIP + ":" + std::to_string(connection.senderPort);
        std::string dst      = connection.receiverIP + ":" + std::to_string(connection.receiverPort);
        std::string proto    = connection.protocol;

        std::string rx       = format_bandwidth(connection.recievedBytes * 8);
        std::string rxPacket = format_packets(connection.recievedPackets);

        std::string tx       = format_bandwidth(connection.transmittedBytes * 8);
        std::string txPacket = format_packets(connection.transmittedPackets);

        // Convert to char* for ncurses
        mvaddstr(row, 0, src.c_str());
        mvaddstr(row, COLS / 2 - 20, dst.c_str());
        mvaddstr(row, COLS - 50, proto.c_str());

        mvaddstr(row, COLS - 40, rx.c_str());
        mvaddstr(row, COLS - 30, rxPacket.c_str());

        mvaddstr(row, COLS - 20, tx.c_str());
        mvaddstr(row, COLS - 10, txPacket.c_str());

        // Move to the next row
        row++;
    }

    Sniffer::clear_communications();
    refresh();
}

void ConsoleUI::alarm_handler(int sig)
{
    ConsoleUI::refresh_data();
}

std::string ConsoleUI::format_packets(double packetsPerSecond)
{
    if (packetsPerSecond < 1000)
    {
        std::stringstream temp;
        temp << std::fixed << std::setprecision(0) << packetsPerSecond;

        return temp.str();
    }
    else
        return round_to_one_decimal(packetsPerSecond / 1000) + "k";
}

std::string ConsoleUI::format_bandwidth(double bitsPerSecond)
{
    // bps, Kbps, Mbps, Gbps 
    const char* units[] = { "", "K", "M", "G" };
    int unitIndex = 0;

    while (bitsPerSecond >= 1000 && unitIndex < 3) 
    {
        bitsPerSecond /= 1000;
        unitIndex++;
    }

    return round_to_one_decimal(bitsPerSecond) + units[unitIndex];
}

std::string ConsoleUI::round_to_one_decimal(double number)
{
    std::stringstream temp;
    temp << std::fixed << std::setprecision(1) << number;

    return temp.str();
}
