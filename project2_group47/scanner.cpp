#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <ctime>

struct sockaddr_in sock_opts(int sock, const std::string&  dest_ip, int timeout_ms);

int socket_creation();

int char_pointer_to_int(char *argument);

void check_ip(const char *argument);

std::vector<int> find_open_ports(struct sockaddr_in destaddr, int from, int to, int sock,
                                 const void *buff, size_t buff_len, int no_of_retries);

struct sockaddr_in sock_opts(int sock, const std::string& dest_ip, int timeout_ms) {
    struct sockaddr_in destaddr;
    destaddr.sin_family = AF_INET;
    inet_aton(dest_ip.c_str(), &destaddr.sin_addr);

    struct timeval tv;
//    timeout of half a second
    tv.tv_sec = 0;
    tv.tv_usec = timeout_ms * 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Could not change socket options");
    }
    return destaddr;    
}

int socket_creation() {
//    The UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
//    If the program cannot open a socket, raise an error and stop.
    if (sock < 0) {
        perror("Cannot open socket");
        return(-1);
    }
    return(sock);
}

/**
 * @see [How to convert a command-line argument to int?](https://stackoverflow.com/a/2797823)
 * @param arg The argument that should be converted into an integer.
 * @return The argument, converted into an integer.
 * @throw An error if the given argument cannot be converted into a number.
 * I.e., it has characters that are not numbers.
 */
int char_pointer_to_int(char *argument) {
    std::string arg(argument);
    try {
        std::size_t pos;
        int result = std::stoi(arg, &pos);
        if (pos < arg.size()) {
            std::cerr << "Trailing characters after number: " << arg << '\n';
        }
        return result;
    } catch (std::invalid_argument const &ex) {
        std::cerr << "Invalid number: " << arg << '\n';
    } catch (std::out_of_range const &ex) {
        std::cerr << "Number out of range: " << arg << '\n';
    }
    throw std::invalid_argument("Invalid argument");
}

/**
 * Turns the argument into a valid ip-address.
 * @throw if the argument is not in a valid ip-address form.
 */
void check_ip(const char *argument) {
    std::string arg(argument);
    std::string delimiter = ".";

    unsigned long prev_ind_occ = 0;
    unsigned long ind_occ = arg.find(delimiter);
    while (ind_occ != std::string::npos) {
        unsigned long ind_diff = ind_occ - prev_ind_occ;
        char *prefix = new char[ind_diff + 1];
        strcpy(prefix, arg.substr(prev_ind_occ, ind_diff).c_str());
        char_pointer_to_int(prefix);
        prev_ind_occ = ind_occ + 1;
        ind_occ = arg.find(delimiter, prev_ind_occ);
    }
    unsigned long ind_diff = arg.size() - prev_ind_occ;
    char *prefix = new char[ind_diff + 1];
    strcpy(prefix, arg.substr(prev_ind_occ).c_str());
    char_pointer_to_int(prefix);
}

std::vector<int> find_open_ports(struct sockaddr_in destaddr, int from, int to, int sock,
        const void *buff, size_t buff_len, int no_of_retries) {
    std::vector<int> open_ports;
    char recv_buff[1400];
    
//    Loop over all requested port numbers
    for (int port_no = from; port_no <= to; port_no++) {
        destaddr.sin_port = htons(port_no);
//        amount of times you want to try and send the message and try to receive one as well.
//        If it didn't receive anything, we conclude that the port is not open.
        int retries = no_of_retries;
        while(retries > 0) {
            try {
                if (sendto(sock, buff, buff_len, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr)) < 0) {
                    perror("Could not send");
                }
                else {
//                    Detects whether anything is received.
                    recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct  sockaddr *) &destaddr,
                             reinterpret_cast<socklen_t *>(sizeof(destaddr)));
//                    Error number 14 means bad address, but it receives the correct info. So it works.
                    if (errno == 14) {
//                        The port is open, so we add the port number to the open ports vector
//                        and the while loop is exited to continue the for loop, to check for other ports.
                        open_ports.push_back(port_no);
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
    }
    return(open_ports);
}

//int main(int argc, char *argv[]) {
////    Default parameters which might be changed depending on how many arguments are given.
//    std::string dest_ip = "130.208.242.120";
////    Start scanning ports from this port number
//    int from = 4000;
////    Until (inclusive) this port number
//    int to = 4100;
////    Take care of given arguments. We want 3 arguments, 'ip-address', 'low port, and 'high port' respectively.
////    The first argument is the ip-address of the destination.
////    The second one is the lowest port it needs to scan activity for.
////    The last argument is the last port, the program needs to scan activity for.
//
////    Too many arguments were given, only use the useful ones. And let the user know they are stupid.
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
//
//    int sock = socket_creation();
//    if (sock == -1) {
//        return(-1);
//    }
//    struct sockaddr_in destaddr = sock_opts(sock, dest_ip);
//
////    The msg sent to the port
//    char buffer[1400];
//    strcpy(buffer, "Hey Port");
//
//    int buff_len = strlen(buffer) + 1;
//
//    printf("The open parts are: ");
//    for (auto el : find_open_ports(destaddr, from, to, sock, buffer, buff_len)) {
//        std::cout << el << ", ";
//    }
//}










/*
//    The UDP socket
    int sock = socket_creation();
    struct sockaddr_in destaddr = sock_opts(sock, dest_ip, timeout_ms);

//use raw socket and then set the header changing ip_off to the value for the evil bit      udphdr
    int raw_socket;
    if(0 > (raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW ))) {
            //printf(“Unable to create a socket”);
            exit(0);
    }

    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &IP_HDRINCL_ON, sizeof(IP_HDRINCL_ON)) < 0) {
                //printf(“Unable to set socket options \n”);
        }






         printf("You have given an insufficient amount of ports. 4 were required but %d were given.\n"
               "The program will scan for ports that are open.\n",
               given_no_of_open_ports);
        */