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
    std::string dest_ip = "130.208.242.120";
//    The secret ports
    int port1 = 4000;
    int port2 = 4000;
    int port3 = 4000;
    int port4 = 4000;
//    Take care of given arguments. We want 3 arguments, 'ip-address', 'low port, and 'high port' respectively.
//    The first argument is the ip-address of the destination.
//    The second one is the lowest port it needs to scan activity for.
//    The last argument is the last port, the program needs to scan activity for.

//    Too many arguments were given, only use the useful ones. And let the user know they are stupid.
//    if (argc > 4) {
//        printf("Too many arguments were given. Only the first 3 will be used. "
//               "Respectively, they are ip-address, low port, and high port.\n");
//    }
//
//    if (argc > 3) {
//        dest_ip = argv[1];
//        check_ip(dest_ip.c_str());
//        from = char_pointer_to_int(argv[2]);
//        to = char_pointer_to_int(argv[3]);
//        if (to < from) {
//            throw std::invalid_argument("High port is lower than low port");
//        }
//    } else if (argc == 3) {
//        dest_ip = argv[1];
//        check_ip(dest_ip.c_str());
//        from = char_pointer_to_int(argv[2]);
//        to = from + 100;
//        printf("You have given 2 arguments, whereas 3 were expected.\n"
//               "The third parameter, 'high port', will be set to: %s\n",
//               std::to_string(to).c_str());
//    } else if (argc == 2) {
//        dest_ip = argv[1];
//        check_ip(dest_ip.c_str());
//        printf("You have given 1 argument, whereas 3 were expected.\n"
//               "The second parameter, 'low port', will be set to: %s\n"
//               "The third parameter, 'high port', will be set to: %s\n",
//               std::to_string(from).c_str(), std::to_string(to).c_str());
//    } else {
//        printf("You have given 0 arguments, whereas 3 were expected.\n"
//               "The first parameter, 'ip-address', will be set to: %s\n"
//               "The second parameter, 'low port', will be set to: %s\n"
//               "The third parameter, 'high port', will be set to: %s\n",
//               dest_ip.c_str(), std::to_string(from).c_str(), std::to_string(to).c_str());
//    }

    int sock = socket_creation();
    if (sock == -1) {
        return(-1);
    }
    struct sockaddr_in destaddr = sock_opts(sock, dest_ip);

//    The msg sent to the port
    char buffer[1400];
    strcpy(buffer, "Hey Port");

    int buff_len = strlen(buffer) + 1;

    std::vector<int> open_ports = find_open_ports(destaddr, 4000, 4100, sock, buffer, buff_len);
    port1 = open_ports[0];
    port2 = open_ports[1];
    port3 = open_ports[2];
    port4 = open_ports[3];

    printf("The open parts are: %d, %d, %d, %d\n", port1, port2, port3, port4);
}