/*****************************************************************//**
 * \file   main.cpp
 * \author Maroš Berdis (xberdi01)
 *********************************************************************/

#include <iostream>
#include <csignal>
#include <signal.h>
#include <iomanip>
#include "ArgumentParser.h"
#include "ConsoleUI.h"
#include "Sniffer.h"

// Function to handle interrupt signal
void signal_handler(int signum) 
{
    Sniffer::stop_capture();
}
    
int main(int argc, char *argv[]) 
{
    // Register signal handler for interrupt signal (Ctrl+C)
    signal(SIGINT, signal_handler);

    // helper variable to check if err occured in object constructors
    bool err = false;

    // Parse CLI arguments
    ArgumentParser options(argc, argv, &err);
    if (err == true)
        return 1;

    // Create sniffer
    Sniffer PacketSniffer(options.get_interface(), &err);
    if (err == true)
        return 1;

    // Create GUI
    ConsoleUI myGUI(options.get_sort_option());

    PacketSniffer.start_capture();

    return 0;
}
