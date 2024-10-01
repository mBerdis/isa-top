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
    RefreshData("");
}

ConsoleUI::~ConsoleUI()
{
    // deallocates memory and ends ncurses
    endwin();
}

void ConsoleUI::RefreshData(const char* row)
{
    alarm(1);   // set alarm for 1 sec

    mvaddstr(0, 0, "SRC IP: PORT");
    mvaddstr(0, 18, "DST IP: PORT");
    mvaddstr(0, 36, "PROTO");
    mvaddstr(0, 50, "Rx");
    mvaddstr(0, 60, "Tx");

    std::string str = std::to_string(Sniffer::i);
    char const* pchar = str.c_str();  //use char const* as target type

    mvaddstr(1, 0, pchar);

    refresh();
}

void ConsoleUI::alarm_handler(int sig)
{
    ConsoleUI::RefreshData("");
}
