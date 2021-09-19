#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <iostream>
#include <vector>

/**
 * @see [How to convert a command-line argument to int?](https://stackoverflow.com/a/2797823)
 * @param arg The argument that should be converted into an integer.
 * @return The argument, converted into an integer.
 * @throw An error if the given argument cannot be converted into a number.
 * I.e., it has characters that are not numbers.
 */
int char_star_to_int(char *argument) {
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
        char_star_to_int(prefix);
        prev_ind_occ = ind_occ + 1;
        ind_occ = arg.find(delimiter, prev_ind_occ);
    }
    unsigned long ind_diff = arg.size() - prev_ind_occ;
    char *prefix = new char[ind_diff + 1];
    strcpy(prefix, arg.substr(prev_ind_occ).c_str());
    char_star_to_int(prefix);
}

int main(int argc, char *argv[]) {
//    Default parameters which might be changed depending on how many arguments are given.
    std::string dest_ip = "130.208.242.120";
//    Start scanning ports from this port number
    int from = 4000;
//    Until (inclusive) this port number
    int to = 4100;
//    Take care of given arguments. We want 3 arguments, 'ip-address', 'low port, and 'high port' respectively.
//    The first argument is the ip-address of the destination.
//    The second one is the lowest port it needs to scan activity for.
//    The last argument is the last port, the program needs to scan activity for.

//    Too many arguments were given, only use the useful ones. And let the user know they are stupid.
    if (argc > 4) {
        printf("Too many arguments were given. Only the first 3 will be used. "
               "Respectively, they are ip-address, low port, and high port.\n");
    }

    if (argc > 3) {
        dest_ip = argv[1];
        check_ip(dest_ip.c_str());
        from = char_star_to_int(argv[2]);
        to = char_star_to_int(argv[3]);
        if (to < from) {
            throw std::invalid_argument("High port is lower than low port");
        }
    } else if (argc == 3) {
        dest_ip = argv[1];
        check_ip(dest_ip.c_str());
        from = char_star_to_int(argv[2]);
        to = from + 100;
        printf("You have given 2 arguments, whereas 3 were expected.\n"
               "The third parameter, 'high port', will be set to: %s\n",
               std::to_string(to).c_str());
    } else if (argc == 2) {
        dest_ip = argv[1];
        check_ip(dest_ip.c_str());
        printf("You have given 1 argument, whereas 3 were expected.\n"
               "The second parameter, 'low port', will be set to: %s\n"
               "The third parameter, 'high port', will be set to: %s\n",
               std::to_string(from).c_str(), std::to_string(to).c_str());
    } else {
        printf("You have given 0 arguments, whereas 3 were expected.\n"
               "The first parameter, 'ip-address', will be set to: %s\n"
               "The second parameter, 'low port', will be set to: %s\n"
               "The third parameter, 'high port', will be set to: %s\n",
               dest_ip.c_str(), std::to_string(from).c_str(), std::to_string(to).c_str());
    }
//    The UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
//    If the program cannot open a socket, raise an error and stop.
    if (sock < 0) {
        perror("Cannot open socket");
        return(-1);
    }

    char buffer[1400];
    struct sockaddr_in destaddr;
//    The msg in the buffer
    strcpy(buffer, "Hey Port");

    int length = strlen(buffer) + 1;

    destaddr.sin_family = AF_INET;
    inet_aton(dest_ip.c_str(), &destaddr.sin_addr);

    std::vector<int> open_ports;
    char recv_buff[1400];

//    Loop over all requested port numbers
    for (int port_no = from; port_no <= to; port_no++) {
        destaddr.sin_port = htons(port_no);

        //int setsockopt(int sockfd);
        setsockopt(sock, 17, SO_RCVTIMEO, 0, sizeof(buffer));
        //getsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tsnd, &ntsnd);
        // amount of times you want to try and send the message
        int retries = 5;
        while(retries > 0) {
            try {
                if (sendto(sock, buffer, length, 0, (const struct  sockaddr *)&destaddr, sizeof(destaddr)) < 0) {
                    perror("Could not send");
                } 
                else {
                    if (recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct  sockaddr *)&destaddr,
                             reinterpret_cast<socklen_t *>(sizeof(destaddr))) > 0) {
                        open_ports.push_back(port_no);
                        break; // success!
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
    std::string open_ports_string(open_ports.begin(), open_ports.end());
    printf("The open ports are:%s\n", open_ports_string.c_str());
}
