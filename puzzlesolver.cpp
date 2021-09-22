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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>


void sendMessage(std::vector<int> open_ports, int sock, char* buffer, std::string dest_ip);


int main(int argc, char *argv[]) {
    int no_of_retries = 20;
//    In milliseconds
    int timeout_ms = 50;
//    Default parameters which might be changed depending on how many arguments are given.
//    Default ip-address
    std::string dest_ip = "130.208.242.120";
//    The secret ports
    std::vector<int> open_ports;

//    The UDP socket
    int sock = socket_creation();
    struct sockaddr_in destaddr = sock_opts(sock, dest_ip, timeout_ms);

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
        int port1 = char_pointer_to_int(argv[2]);
        int port2 = char_pointer_to_int(argv[3]);
        int port3 = char_pointer_to_int(argv[4]);
        int port4 = char_pointer_to_int(argv[5]);

        open_ports.push_back(port1);
        open_ports.push_back(port2);
        open_ports.push_back(port3);
        open_ports.push_back(port4);
    } else {
        int given_no_of_open_ports = 0;
        if (argc > 1) {
            given_no_of_open_ports = argc - 2;
        }
        printf("You have given an insufficient amount of ports. 4 were required but %d were given.\n"
               "The program will scan for ports that are open.\n",
               given_no_of_open_ports);
        if (argc == 2) {
            dest_ip = argv[1];
            check_ip(dest_ip.c_str());
        } else {
            printf("You have not entered an ip-address. The default ip-address will be used. This is %s.\n",
                   dest_ip.c_str());
        }

        int from = 4000;
        int to = 4100;
        open_ports = find_open_ports(destaddr, from, to, sock, buffer, buff_len, no_of_retries);
    }

    sendMessage(open_ports, sock, buffer, dest_ip);

}


void sendFinalmessage(std::vector<int> open_ports, int sock, char* buffer, std::string dest_ip, int message_option, int port_nr) {
    struct sockaddr_in destaddr;
    // converting int to char const
    char const *port_char = std::to_string(open_ports[0]).c_str();
    strcpy(buffer, port_char);

    if(message_option == 1){
        strcpy(buffer, "group_47");
    }
        // Send to secret port. Message: My boss told me not to tell anyone that my secret port is port nr
    else if(message_option == 2){
        strcpy(buffer, "port_nr something");
    }
    //  The msg in the buffer
    int length = strlen(buffer) + 1;
    destaddr.sin_family = AF_INET;
    inet_aton(dest_ip.c_str(), &destaddr.sin_addr);
    char recv_buff[1400];
    destaddr.sin_port = htons(open_ports[port_nr]);
    //  amount of times you want to try and send the message and try to receive one as well.
    //  If it didn't receive anything, we conclude that the port is not open.
    int retries = 20;
    while(retries > 0) {
        try {
            if (sendto(sock, buffer, length, 0, (const struct  sockaddr *)&destaddr, sizeof(destaddr)) < 0) {
                perror("Could not send");
            }
            else {
//                    Detects whether anything is received.
                recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct  sockaddr *) &destaddr,
                         reinterpret_cast<socklen_t *>(sizeof(destaddr)));
                char first_variable = recv_buff[0];
//                    Error number 14 means bad address, but it receives the correct info. So it works.
                if (errno == 14) {
                    break;
                }
                break;
            }
            retries--;
        }
        catch(const std::overflow_error& e){
            throw "could not send";
        }
    }
}

void sendMessage(std::vector<int> open_ports, int sock, char* buffer, std::string dest_ip) {

    for(int i; i<4; i++){
        struct sockaddr_in destaddr;
        //  The msg in the buffer
        strcpy(buffer, "Hey Port");
        int length = strlen(buffer) + 1;
        destaddr.sin_family = AF_INET;
        inet_aton(dest_ip.c_str(), &destaddr.sin_addr);
        char recv_buff[1400];
        destaddr.sin_port = htons(open_ports[i]);
        //  amount of times you want to try and send the message and try to receive one as well.
        //  If it didn't receive anything, we conclude that the port is not open.
        int retries = 20;
        while(retries > 0) {
            try {
                if (sendto(sock, buffer, length, 0, (const struct  sockaddr *)&destaddr, sizeof(destaddr)) < 0) {
                    perror("Could not send");
                }
                else {
//                    Detects whether anything is received.
                    recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct  sockaddr *) &destaddr,
                             reinterpret_cast<socklen_t *>(sizeof(destaddr)));
                    char first_variable = recv_buff[0];
//                    Error number 14 means bad address, but it receives the correct info. So it works.
                    if (errno == 14) {
//                        The port is open, so we add the port number to the open ports vector
//                        and the while loop is exited to continue the for loop, to check for other ports.
                        open_ports.push_back(open_ports[i]);
                        break;
                    }
                    memset(recv_buff, 0, sizeof(recv_buff));
                    if (i == 2 || i == 3){
                        // Send "group_47"
                        sendFinalmessage(open_ports, sock, buffer, dest_ip, 1, i);
                    }
                    else if (i == 4){
                        // send .... (we don't know yet)
                        sendFinalmessage(open_ports, sock, buffer, dest_ip, 2, i);
                    }
                    memset(recv_buff, 0, sizeof(recv_buff));
                    break;
                }
                retries--;
            }
            catch(const std::overflow_error& e){
                throw "could not send";
            }
        }
    }
}