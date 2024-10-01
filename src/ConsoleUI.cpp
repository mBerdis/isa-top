#include "ConsoleUI.h"
#include <ncurses.h>
#include <string>
#include <vector>

ConsoleUI::ConsoleUI()
{
    // init screen and sets up screen
    initscr();

    // Refresh the screen to show changes
    refresh();
}

ConsoleUI::~ConsoleUI()
{
    // deallocates memory and ends ncurses
    endwin();
}

void ConsoleUI::RefreshData(const char* row)
{

    mvaddstr(0, 0, "SRC IP: PORT");
    mvaddstr(0, 18, "DST IP: PORT");
    mvaddstr(0, 36, "PROTO");
    mvaddstr(0, 50, "Rx");
    mvaddstr(0, 60, "Tx");
    mvaddstr(1, 0, row);

    refresh();
}
