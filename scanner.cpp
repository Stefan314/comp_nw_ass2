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
using namespace std;

int noOfRetries = 10;
// In milliseconds
int timeout = 400;
// Used for testing TODO: Set to true in final version.
bool debugOverride = false;

struct sockaddr_in sockOpts(int sock, const string &dest_ip);

int socketCreation();

bool checkIp(const string& argument);

vector<int> findOpenPorts(const string &dest_ip, int from, int to, int sock, int max_ports);

vector<string> sendAndReceive(int sock, char *buffer, const string &dest_ip, const vector<int>& dest_ports);

string sendAndReceive(int sock, char *buffer, const string &dest_ip, int dest_port);

void debugPrint(const string &arg_name, const string &arg, bool debug);

void debugPrint(const string &arg_name, unsigned long arg, bool debug);

vector<string> split(const string& str_to_split, const string& delim);

vector<int> stringVecToIntVec(const vector<string>& str_vec);

void runScanner(int argc, char *argv[]);

// TODO: UNCOMMENT THIS FOR THE FINAL VERSION
//int main(int argc, char *argv[]) {
//    runScanner(argc, argv);
//}

void runScanner(int argc, char *argv[]) {
/* Default parameters which might be changed depending on how many arguments are given.
 * This is handy for testing, and for when the user did not give enough parameters. */

//    Default ip
    string dest_ip = "130.208.242.120";
//    Start scanning ports from this port number
    int from = 4000;
//    Until (inclusive) this port number
    int to = 4100;
/* Take care of given arguments. We want 3 arguments, 'ip-address', 'low port, and 'high port' respectively.
 * The first argument is the ip-address of the destination.
 * The second one is the lowest port it needs to scan activity for.
 * The last argument is the last port, the program needs to scan activity for. */

//    Too many arguments were given, only use the useful ones. And let the user know they are stupid.
    if (argc > 4) {
        printf("Too many arguments were given. Only the first 3 will be used. "
               "Respectively, they are ip-address, low port, and high port.\n");
    }

    if (argc > 3) {
        dest_ip = argv[1];
        checkIp(dest_ip);
        from = stoi(argv[2], nullptr, 10);
        to = stoi(argv[3], nullptr, 10);
        if (to < from) {
            throw invalid_argument("High port is lower than low port");
        }
    }
    else if (argc == 3) {
        dest_ip = argv[1];
        checkIp(dest_ip);
        from = stoi(argv[2], nullptr, 10);
        to = from + 100;
        printf("You have given 2 arguments, whereas 3 were expected.\n"
               "The third parameter, 'high port', will be set to: %s\n",
               to_string(to).c_str());
    }
    else if (argc == 2) {
        dest_ip = argv[1];
        checkIp(dest_ip);
        bool potato = true;
        printf("You have given 1 argument, whereas 3 were expected.\n"
               "The second parameter, 'low port', will be set to: %s\n"
               "The third parameter, 'high port', will be set to: %s\n",
               to_string(from).c_str(), to_string(to).c_str());
    }
    else {
        printf("You have given 0 arguments, whereas 3 were expected.\n"
               "The first parameter, 'ip-address', will be set to: %s\n"
               "The second parameter, 'low port', will be set to: %s\n"
               "The third parameter, 'high port', will be set to: %s\n",
               dest_ip.c_str(), to_string(from).c_str(), to_string(to).c_str());
    }

    int sock = socketCreation();
    if (sock == -1) {
        perror("socket was not created.");
    }
    sockOpts(sock, dest_ip);

    printf("The open parts are: ");
    for (auto el : findOpenPorts(dest_ip, from, to, sock, 4)) {
        cout << el << ", ";
    }
}

struct sockaddr_in sockOpts(int sock, const string &dest_ip) {
    struct sockaddr_in dest_address{};
    dest_address.sin_family = AF_INET;
    inet_aton(dest_ip.c_str(), &dest_address.sin_addr);

    struct timeval tv{};
//    timeout of half a second
    tv.tv_sec = 0;
    tv.tv_usec = timeout * 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Could not change socket options");
    }
    return dest_address;
}

int socketCreation() {
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
 * Finds whether the given string is in the form of an IP-address. (digits separated by periods)
 * @return if the given string is a correctly formed ip-address
 */
bool checkIp(const string& argument) {
    try {
        vector<string> ip_bytes = split(argument, ".");
        vector<int> ip_as_ints = stringVecToIntVec(ip_bytes);
    } catch (...) {
//        If the conversion did not work, the IP-address is formatted incorrectly.
        return false;
    }
    return true;
}

vector<int> findOpenPorts(const string &dest_ip, int from, int to, int sock, int max_ports) {
//    The msg sent to the port
    char buffer[1400];
    strcpy(buffer, "Hey Port");
    vector<int> open_ports;
    
//    Loop over all requested port numbers
    for (int port_no = from; port_no <= to; port_no++) {
        string response = sendAndReceive(sock, buffer, dest_ip, port_no);
        if (!response.empty()) {
            open_ports.push_back(port_no);
        }
        if (open_ports.size() == max_ports) {
            break;
        }
    }
    return(open_ports);
}

/**
 * Tries to send a message and receive the response to the ports in the same order they are given in
 * @param sock The socket it needs to send the messages to
 * @param buffer The message that needs to be sent.
 * @param dest_ip The ip-address that needs to receive the message.
 * @param dest_ports The ports that the message need to be sent to.
 * @return The received message if there is any. If there is no response, then it will return the empty string.
 */
vector<string> sendAndReceive(int sock, char *buffer, const string &dest_ip, const vector<int>& dest_ports) {
//    Stores all the responses inside this vector.
    vector<string> responses;
/* This character represents the first character of the message saying that there was a checksum error server-side.
 * The program will retry that port. */
    char error_char = 'R';
    struct sockaddr_in dest_address{};
    dest_address.sin_family = AF_INET;
    inet_aton(dest_ip.c_str(), &dest_address.sin_addr);
    char receive_buff[1400];
/* Amount of times you want to try and send the message and try to receive one as well.
 * If it didn't receive anything, we conclude that the port is not open. */
    for (int i = 0; i < noOfRetries; i++)  {
//        Sends the ports in the given order
        for (auto&& dest_port : dest_ports) {
            dest_address.sin_port = htons(dest_port);
            try {
                if (sendto(sock, buffer, strlen(buffer), 0, (const struct sockaddr *) &dest_address,
                           sizeof(dest_address)) < 0) {
//                    Could not send the msg
                    perror("Could not send");
                }
                else {
//                    Detects whether anything is received.
                    memset(receive_buff, 0, sizeof(receive_buff));
                    struct sockaddr_in receive_address{};
                    socklen_t address_len = sizeof(receive_address);
                    ssize_t output_len = recvfrom(sock, receive_buff, sizeof(receive_buff), 0,
                                                  (struct sockaddr*)&receive_address, &address_len);
                    string sender_ip = inet_ntoa(receive_address.sin_addr);
                    unsigned int sender_port = ntohs(receive_address.sin_port);
                    debugPrint("sender ip", inet_ntoa(receive_address.sin_addr), false);
                    debugPrint("sender port", ntohs(receive_address.sin_port), false);

//                    Ensures that we get the message from the correct ip and port
                    if (output_len > 0 and sender_ip == dest_ip and sender_port == dest_port) {
                        debugPrint("receive_buff", receive_buff, false);
                        char first_char = receive_buff[0];
                        if (first_char == error_char) {
//                            There is a random checksum error server-side. Try sending and receiving again.
                            break;
                        }
                        responses.emplace_back(receive_buff);
                    }
                }
            }
            catch (const overflow_error &e) {
                throw overflow_error("could not send");
            }
        }
        if (responses.size() == dest_ports.size()) {
            return responses;
        } else {
            responses.clear();
        }
    }
    return responses;
}

/**
 * Tries to send a message and receive the response to the given port
 * @param sock The socket it needs to send the message to
 * @param buffer The message that needs to be sent.
 * @param dest_ip The ip-address that needs to receive the message.
 * @param dest_port The port that the message need to be sent to.
 * @return The received message if there is any. If there is no response, then it will be the empty string.
 */
string sendAndReceive(int sock, char *buffer, const string &dest_ip, int dest_port) {
    vector<int> dest_ports;
    dest_ports.push_back(dest_port);
    return sendAndReceive(sock, buffer, dest_ip, dest_ports)[0];
}

void debugPrint(const string &arg_name, const string &arg, bool debug) {
    if (!debugOverride && debug) {
        cout << arg_name + "=" << arg << "\n";
    }
}

void debugPrint(const string &arg_name, unsigned long arg, bool debug) {
    debugPrint(arg_name, to_string(arg), debug);
}

vector<string> split(const string& str_to_split, const string& delim) {
    vector<string> split_string;

    unsigned long prev_occur_idx = 0;
    unsigned long occur_idx = str_to_split.find(delim);
    while (occur_idx != string::npos) {
        unsigned long ind_diff = occur_idx - prev_occur_idx;
        string string_before_delim = str_to_split.substr(prev_occur_idx, ind_diff);
        split_string.push_back(string_before_delim);
        prev_occur_idx = occur_idx + delim.size();
        occur_idx = str_to_split.find(delim, prev_occur_idx);
    }
    unsigned long ind_diff = occur_idx - prev_occur_idx;
    string string_before_delim = str_to_split.substr(prev_occur_idx, ind_diff);
    split_string.push_back(string_before_delim);

    return split_string;
}

vector<int> stringVecToIntVec(const vector<string>& str_vec) {
    vector<int> result;

    result.reserve(str_vec.size());
    for (const string& str : str_vec) {
        result.push_back(stoi(str, nullptr, 10));
    }
    return result;
}
