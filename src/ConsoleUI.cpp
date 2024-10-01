#include "ConsoleUI.h"
//#include <ncurses.h>
#include <curses.h>
#include <string>
#include <vector>
#include <iostream>
#include <signal.h>
#include "Sniffer.h"

ConsoleUI::ConsoleUI()
{
    initscr();            // Initialize ncurses
    cbreak();             // Disable line buffering, but still allow Ctrl+C
    noecho();             // Don't echo input to the terminal
    keypad(stdscr, FALSE); // Disable special input handling like arrow keys
    timeout(-1);          // Don't wait for user input (disable input completely)

    signal(SIGALRM, alarm_handler);

    // Refresh the screen to show changes
    RefreshData();
}

ConsoleUI::~ConsoleUI()
{
    // deallocates memory and ends ncurses
    endwin();
}

void ConsoleUI::RefreshData()
{
    alarm(1);   // set alarm for 1 sec

    // Clear the screen before printing
    clear();

    mvaddstr(0, 0, "SRC IP: PORT");
    mvaddstr(0, 18, "DST IP: PORT");
    mvaddstr(0, 36, "PROTO");
    mvaddstr(0, 50, "Rx");
    mvaddstr(0, 60, "Tx");

    int row = 1;  // Start printing from the second row

    // Iterate through the map
    for (const auto& entry : Sniffer::get_communications())
    {
        const std::string& key = entry.first;
        const ConnectionInfo& connection = entry.second;

        // Format the data as strings
        std::string src = connection.senderIP + ":" + std::to_string(connection.senderPort);
        std::string dst = connection.receiverIP + ":" + std::to_string(connection.receiverPort);
        std::string proto = connection.protocol;
        std::string rx = std::to_string(connection.totalBytes) + "B";  // Example Rx value (bytes)
        //std::string tx = std::to_string(connection.totalBytesSent) + "B";  // Example Tx value (bytes)

        // Convert to char* for ncurses
        mvaddstr(row, 0, src.c_str());
        mvaddstr(row, 18, dst.c_str());
        mvaddstr(row, 36, proto.c_str());
        mvaddstr(row, 50, rx.c_str());
        //mvaddstr(row, 60, tx.c_str());

        // Move to the next row
        row++;
    }

    Sniffer::clear_communications();
    refresh();
}

void ConsoleUI::alarm_handler(int sig)
{
    ConsoleUI::RefreshData();
}
