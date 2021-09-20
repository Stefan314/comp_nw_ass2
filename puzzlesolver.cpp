//
// Created by Stefan on 18/09/2021.
//

#include <netinet/in.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <iostream>
#include <vector>
#include "scanner.h"

int main(int argc, char *argv[]) {
//    Default parameters which might be changed depending on how many arguments are given.
//    Default ip-address
    std::string dest_ip = "130.208.242.120";
//    The secret ports
    int port1 = 4000;
    int port2 = 4000;
    int port3 = 4000;
    int port4 = 4000;

//    The socket
    int sock = socket_creation();
    if (sock == -1) {
        return(-1);
    }
    struct sockaddr_in destaddr = sock_opts(sock, dest_ip);

//    The msg sent to the port
    char buffer[1400];
    strcpy(buffer, "Hey Port");

    int buff_len = strlen(buffer) + 1;
//    Take care of given arguments. We want 1 or 4 arguments, 'ip-address',
//    and optional 'port 1', 'port 2', 'port 3', and 'port 4' respectively.
//    The first argument is the ip-address of the destination.
//    The ones after that are the open ports.

//    Too many arguments were given, only use the useful ones. And let the user know they are stupid.
    if (argc > 6) {
        printf("Too many arguments were given. Only the first 5 will be used. "
               "Respectively, they are ip-address, port 1, port 2, port 3, and port 4.\n");
    }

    if (argc > 5) {
        dest_ip = argv[1];
        check_ip(dest_ip.c_str());
        port1 = char_pointer_to_int(argv[2]);
        port2 = char_pointer_to_int(argv[3]);
        port3 = char_pointer_to_int(argv[4]);
        port4 = char_pointer_to_int(argv[5]);
    } else {
        int given_no_of_open_ports = 0;
        if (argc > 1) {
            given_no_of_open_ports = argc - 2;
        }
        printf("You have given an insufficient amount of ports. 4 were required but %d were given.\n"
               "The program will scan for ports that are open.\n"
                , given_no_of_open_ports);
        if (argc == 2) {
            dest_ip = argv[1];
            check_ip(dest_ip.c_str());
        } else {
            printf("You have not entered an ip-address. The default ip-address will be used. This is %s.\n"
                    , dest_ip.c_str());
        }

        int from = 4000;
        int to = 4100;
        std::vector<int> open_ports = find_open_ports(destaddr, from, to, sock, buffer, buff_len);
        port1 = open_ports[0];
        port2 = open_ports[1];
        port3 = open_ports[2];
        port4 = open_ports[3];
    }

    printf("The open parts are: %d, %d, %d, %d\n", port1, port2, port3, port4);
}