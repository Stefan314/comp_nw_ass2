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

int NO_OF_RETRIES = 10;

void sendMessage(std::vector<int> open_ports, int sock, char *buffer, std::string dest_ip);


int main(int argc, char *argv[]) {
//    In milliseconds
    int timeout_ms = 200;
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
        open_ports.push_back(char_pointer_to_int(argv[2]));
        open_ports.push_back(char_pointer_to_int(argv[3]));
        open_ports.push_back(char_pointer_to_int(argv[4]));
        open_ports.push_back(char_pointer_to_int(argv[5]));
    } else {
        int given_no_of_open_ports = 0;
        const char* dest_ip_c = dest_ip.c_str();
        if (argc > 1) {
            given_no_of_open_ports = argc - 2;
            dest_ip = argv[1];
            check_ip(dest_ip_c);
        } else {
            printf("You have not entered an ip-address. The default ip-address will be used. This is %s.\n",
                   dest_ip_c);
        }
        printf("You have given an insufficient amount of ports. 4 were required but %d were given.\n"
               "The program will scan for ports that are open.\n",
               given_no_of_open_ports);

        int from = 4000;
        int to = 4100;
//        open_ports = find_open_ports(destaddr, from, to, sock, buffer, buff_len, NO_OF_RETRIES);

        open_ports.push_back(4003);
        open_ports.push_back(4012);
        open_ports.push_back(4041);
        open_ports.push_back(4042);
    }

    sendMessage(open_ports, sock, buffer, dest_ip);

}


std::string sendFinalmessage(int sock, char* buffer, std::string dest_ip, int port_nr) {
    std::string result = "";

    struct sockaddr_in destaddr;
    //  The msg in the buffer
    int buff_len = strlen(buffer) + 1;
    destaddr.sin_family = AF_INET;
    inet_aton(dest_ip.c_str(), &destaddr.sin_addr);
    char recv_buff[1400];
    destaddr.sin_port = htons(port_nr);
    //  amount of times you want to try and send the message and try to receive one as well.
    //  If it didn't receive anything, we conclude that the port is not open.
    int retries = NO_OF_RETRIES;
    while (retries > 0) {
        try {
            if (sendto(sock, buffer, buff_len, 0, (const struct  sockaddr *)&destaddr, sizeof(destaddr)) < 0) {
                perror("Could not send");
            } else {
//               Detects whether anything is received.
                recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct  sockaddr *) &destaddr,
                         reinterpret_cast<socklen_t *>(sizeof(destaddr)));

//              Error number 14 means bad address, but it receives the correct info. So it works.
                if (errno == 14) {
//                    printf("%s\n", recv_buff);
                    memset(recv_buff, 0, sizeof(recv_buff));
                    break;
                }
                memset(recv_buff, 0, sizeof(recv_buff));
            }
            retries--;
        }
        catch(const std::overflow_error& e){
            throw "could not send";
        }
    }
    return result;
}

void sendMessage(std::vector<int> open_ports, int sock, char *buffer, std::string dest_ip) {
//    This is the port we need to send the comma seperated list of secret ports to.
    int csl_port = open_ports[0];

    //    Send comma separated list
    char key_char1 = 'I';
    //    Send $group_47$
//    Receive:
//    Hello, group_47! To get the secret phrase, send me a udp message where the payload is a valid UDP IPv4 packet,
//    that has a valid UDP checksum of 0x7a29, and with the source address being 47.29.57.150!
//    (the last 6 bytes of this message contain this information in network order)z)/9
    char key_char2 = 'S';
    //    Send $group_47$, with evil bit
    char key_char3 = 'T';
    //    Find secret port, recv_buff[-5:-1]
    char key_char4 = 'M';
    std::vector<std::string> secret_ports;

    for (int i; i < 4; i++) {
        int curr_port = open_ports[i];
        struct sockaddr_in destaddr;
        //  The msg in the buffer
        strcpy(buffer, "Hey Port");
        int length = strlen(buffer) + 1;
        destaddr.sin_family = AF_INET;
        inet_aton(dest_ip.c_str(), &destaddr.sin_addr);
        char recv_buff[1400];
        destaddr.sin_port = htons(curr_port);
        //  amount of times you want to try and send the message and try to receive one as well.
        //  If it didn't receive anything, we conclude that the port is not open.
        int retries = NO_OF_RETRIES;
        while (retries > 0) {
            try {
                if (sendto(sock, buffer, length, 0, (const struct  sockaddr *)&destaddr, sizeof(destaddr)) < 0) {
                    perror("Could not send");
                } else {
//                    Detects whether anything is received.
                    recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct  sockaddr *) &destaddr,
                             reinterpret_cast<socklen_t *>(sizeof(destaddr)));
//                    Error number 14 means bad address, but it receives the correct info. So it works.
                    if (errno == 14) {
//                        The port is open, so we add the port number to the open ports vector
//                        and the while loop is exited to continue the for loop, to check for other ports.
                        char first_char = recv_buff[0];
                        if (first_char == key_char1) {
                            csl_port = curr_port;
                        } else if (first_char == key_char2) {
                            // Send "group_47"
//    The msg sent to the port that should receive the group number
//                            TODO: Fix the returned msg
                            char buff_special_msg[1400];
                            strcpy(buff_special_msg, "$group_47$");
                            secret_ports.push_back(sendFinalmessage(sock, buff_special_msg, dest_ip, curr_port));
                        } else if (first_char == key_char3) {
//                            TODO: Send evil bit
                        } else if (first_char == key_char4) {
                            // Find secret port in recv buffer
                            std::string sec_port;
                            int recv_buff_len = sizeof(recv_buff) / sizeof(recv_buff[0]);
                            for (int j = 0; j < recv_buff_len; j++) {
                                char el = recv_buff[j];
                                if (el == '4') {
                                    for (int k = j; k < j + 4; k++) {
                                        char char_to_add = recv_buff[k];
                                        sec_port += char_to_add;
                                    }
                                    break;
                                }
                            }
                            secret_ports.push_back(sec_port);
                        }
                        memset(recv_buff, 0, sizeof(recv_buff));
                        break;
                    }
                    memset(recv_buff, 0, sizeof(recv_buff));
                }
                retries--;
            }
            catch (const std::overflow_error& e) {
                throw "could not send";
            }
        }
    }
    std::string secret_ports_csl;
    for (int i = 0; i < secret_ports.size(); i++) {
        std::cout << secret_ports[i].c_str() << " boo\n";
        secret_ports_csl += secret_ports[i];
        if (i < secret_ports.size() - 1) {
            secret_ports_csl += ", ";
        }
    }
    std::cout << secret_ports_csl.c_str() << "\n";
    char buff_special_msg[1400];
    strcpy(buff_special_msg, secret_ports_csl.c_str());
    sendFinalmessage(sock, buff_special_msg, dest_ip, csl_port);
}