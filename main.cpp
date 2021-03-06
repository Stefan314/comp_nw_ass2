//
// Created by stefan on 26/09/2021.
//
#include "scanner.h"
#include "puzzlesolver.h"
using namespace std;

const int scanner = 0;
const int puzzleSolver = 1;

const int programToRun = puzzleSolver;
#define IP_EVIL	0x8000		/* Flag: "reserve bit"	*/
//
// Created by Stefan on 18/09/2021.
//

#include <sys/ioctl.h>
#include <net/if.h>
#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
//#include <net/if.h>
#include <sys/socket.h>
//#include <string.h>
///

#include <netinet/in.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <iostream>
#include <utility>
#include <vector>
#include "scanner.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <bitset>
#include <cmath>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <algorithm>
using namespace std;
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

struct sockaddr_in sockOpts(int sock, const string &destIP);

int socketCreation();

bool checkIp(const string& argument);

vector<int> findOpenPorts(const string &destIP, int from, int to, int sock, int max_ports);

vector<string> sendAndReceive(int sock, char *buffer, const string &destIP, const vector<int>& dest_ports);

string sendAndReceive(int sock, char *buffer, const string &dest_ip, int dest_port);

void debugPrint(const string &argName, const string &arg, bool debug);

void debugPrint(const string &argName, unsigned long arg, bool debug);

vector<string> split(const string& strToSplit, const string& delim);

vector<int> stringVecToIntVec(const vector<string>& strVec);

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

struct sockaddr_in sockOpts(int sock, const string &destIP) {
    struct sockaddr_in dest_address{};
    dest_address.sin_family = AF_INET;
    inet_aton(destIP.c_str(), &dest_address.sin_addr);

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

vector<int> findOpenPorts(const string &destIP, int from, int to, int sock, int max_ports) {
//    The msg sent to the port
    char buffer[1400];
    strcpy(buffer, "Hey Port");
    vector<int> open_ports;
    
//    Loop over all requested port numbers
    for (int port_no = from; port_no <= to; port_no++) {
        string response = sendAndReceive(sock, buffer, destIP, port_no);
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
 * @param destIP The ip-address that needs to receive the message.
 * @param dest_ports The ports that the message need to be sent to.
 * @return The received message if there is any. If there is no response, then it will return the empty string.
 */
vector<string> sendAndReceive(int sock, char *buffer, const string &destIP, const vector<int>& dest_ports) {
//    Stores all the responses inside this vector.
    vector<string> responses;
/* This character represents the first character of the message saying that there was a checksum error server-side.
 * The program will retry that port. */
    char error_char = 'R';
    struct sockaddr_in dest_address{};
    dest_address.sin_family = AF_INET;
    inet_aton(destIP.c_str(), &dest_address.sin_addr);
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
                    if (output_len > 0 and sender_ip == destIP and sender_port == dest_port) {
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

void debugPrint(const string &argName, const string &arg, bool debug) {
    if (!debugOverride && debug) {
        cout << argName + "=" << arg << "\n";
    }
}

void debugPrint(const string &argName, unsigned long arg, bool debug) {
    debugPrint(argName, to_string(arg), debug);
}

vector<string> split(const string& strToSplit, const string& delim) {
    vector<string> split_string;

    unsigned long prev_occur_idx = 0;
    unsigned long occur_idx = strToSplit.find(delim);
    while (occur_idx != string::npos) {
        unsigned long ind_diff = occur_idx - prev_occur_idx;
        string string_before_delim = strToSplit.substr(prev_occur_idx, ind_diff);
        split_string.push_back(string_before_delim);
        prev_occur_idx = occur_idx + delim.size();
        occur_idx = strToSplit.find(delim, prev_occur_idx);
    }
    unsigned long ind_diff = occur_idx - prev_occur_idx;
    string string_before_delim = strToSplit.substr(prev_occur_idx, ind_diff);
    split_string.push_back(string_before_delim);

    return split_string;
}

vector<int> stringVecToIntVec(const vector<string>& strVec) {
    vector<int> result;

    result.reserve(strVec.size());
    for (const string& str : strVec) {
        result.push_back(stoi(str, nullptr, 10));
    }
    return result;
}

///////////////////////////////////
// TODO: Remove unused methods in the end.

bool hardCodeHiddenPorts = true;
// Used for testing TODO: Set all to false in final version.
bool hardCodedPorts = true;
bool testCustomHeader = false;
// The payload if the program needs to send the group number.
const char *groupNumber = "$group_47$";

/**
 * Clion got upset when I declared this as a global variable, so it's made into a function.
 * @return All the hexadecimal characters in order.
 */
string getHexChars() {
    return "0123456789abcdef";
}

void messageHandler(const vector<int>& openPorts, int sock, char *buffer, const string& destIP);

bool binLarger(string bin1, string bin2);

string binDiff(string bin1, const string& bin2);

uint16_t removeShortOverflow(uint32_t header_sum);

uint16_t adaptedUDPSrcPort(udphdr *udp_hdr, const string& srcIP, const string& destIP);

string invBin(string bin);

string hexToBin(const string& hexadecimalString);

string decrementBin(string bin, int decrement);

string incrementHex(string hex, int increment);

string binToHex(const string& bin);

string decrementHex(string hex, unsigned int decrement);

string hexAddition(string hex1, const string& hex2);

string hextetSum(const string& hex);

string invHex(const string& hex);

string ipToBin(const string& ip);

uint16_t ipChecksum(struct iphdr ip_hdr);

string createCorrectId(const string& desiredChecksum, const string& calcChecksum);

char binToChar(const string& bin);

string binToCharString(const string& bin);

string checksumPortHandler(int sock, const string &destIP, const int &port);

void evilPortHandler(int sock, const string &destIP, const int &port);

string checksumPortHandler2(int sock, string response, const string& destIP, int port);

string checksumPortHandler3(int sock, const string &destIP, int port, const string& newUDPChecksum,
                            const string& newSrcIp);

string oraclePortHandler(int sock, vector<string> secret_ports, const string &destIP, int port,
                         const string& secretMsg);

string oraclePortHandler2(int sock, const string &destIP, string previous_response, const string& secretMsg);

void runPuzzle(int argc, char *argv[]);

string oraclePortHandler3(int sock, const string &destIp, vector<string> responses, const vector<int> &portKnox,
                          const string& secretMsg);

// TODO: UNCOMMENT FOR THE FINAL VERSION
///**
// * @see runPuzzle()
// */
//int main(int argc, char *argv[]) {
//    runPuzzle(argc, argv);
//}

const char * createHeaders(const string &newSrcIP, const string &destIP, unsigned int flag,
                           const string &newUDPChecksum, int port);

/**
 * Main method that runs the code. Is originally used for easy testing, now it is just the forwarded actual main method.
 * @param argc The number of arguments, the user gave on the command line.
 * Only from the 2nd argument onwards, the arguments are usable, since the first argument is just the command itself.
 * @param argv The arguments, the user gave on the command line.
 * Only from the 2nd argument onwards, the arguments are usable, since the first argument is just the command itself.
 */
void runPuzzle(int argc, char *argv[]) {
//    Default ip-address, in case the user did not enter any parameters.
    string dest_ip = "130.208.242.120";
//    The secret ports
    vector<int> open_ports;

//    The UDP socket
    int sock = socketCreation();
    struct sockaddr_in dest_address = sockOpts(sock, dest_ip);

//    The msg sent to the port
    char buffer[1400];
    int buff_len = sizeof(buffer);
    strcpy(buffer, "Hey Port");
/* Take care of given arguments. We want 1 or 4 arguments, 'ip-address',
 * and optional 'port 1', 'port 2', 'port 3', and 'port 4' respectively.
 * The first argument is the ip-address of the destination.
 * The ones after that are the open ports. */

//    Too many arguments were given, only use the useful ones. And let the user know they are stupid.
    if (argc > 6) {
        printf("Too many arguments were given. Only the first 5 will be used. "
               "Respectively, they are ip-address, port 1, port 2, port 3, and port 4.\n");
    }

    if (argc > 5) {
        dest_ip = argv[1];
        checkIp(dest_ip);
        open_ports.push_back(stoi(argv[2], nullptr, 10));
        open_ports.push_back(stoi(argv[3], nullptr, 10));
        open_ports.push_back(stoi(argv[4], nullptr, 10));
        open_ports.push_back(stoi(argv[5], nullptr, 10));
    } else {
        int given_no_of_open_ports = 0;
        if (argc > 1) {
            given_no_of_open_ports = argc - 2;
            dest_ip = argv[1];
            const char* dest_ip_c = dest_ip.c_str();
            checkIp(dest_ip_c);
        } else {
            const char* dest_ip_c = dest_ip.c_str();
            printf("You have not entered an ip-address. The default ip-address will be used. This is %s.\n",
                   dest_ip_c);
        }
        printf("You have given an insufficient amount of ports. 4 were required but %d were given.\n"
               "The program will scan for ports that are open.\n",
               given_no_of_open_ports);

        int from = 4000;
        int to = 4100;
        if (hardCodedPorts) {
            open_ports.push_back(4042);
            open_ports.push_back(4097);
            open_ports.push_back(4098);
            open_ports.push_back(4099);
        } else {
            open_ports = findOpenPorts(dest_ip, from, to, sock, 4);
        }
    }
    messageHandler(open_ports, sock, buffer, dest_ip);
}

/**
 * Converts a hexadecimal to a binary number.
 * Partially inspired by user https://stackoverflow.com/users/1951468/silex on thread
 * https://stackoverflow.com/questions/18310952/convert-strings-between-hexadecimalString-format-and-binary-format
 * @param hexadecimalString The string representation of a hexadecimal number.
 * @return The hexadecimal number, converted to binary.
 */
string hexToBin(const string& hexadecimalString) {
    string bin;
//    Loops over each hexadecimal character, converts it to its binary form and appends it to the binary string.
    for (auto&& hexadecimal : hexadecimalString) {
        stringstream stream;
        stream << hex << hexadecimal;
        unsigned result;
        stream >> result;
//        4, because hexadecimal is base 16, which is 2^4, so 4 bits
        bitset<4> b(result);
        bin += b.to_string();
    }
    return bin;
}

/**
 * Decreases the binary string by the given amount.
 * @param bin The binary string
 * @param decrement The amount the binary string needs to be decreased by
 * @return A new binary string, decreased by the specified amount.
 * If the given decrement is larger than the number the binary string represents,
 * then it will return the empty string. It also does not keep the original size.
 * Namely, it will remove any trailing 0's.
 */
string decrementBin(string bin, int decrement) {
    for (int i = 0; i < decrement; i++) {
        char last_bit = bin[bin.size() - 1];
        string replacement = "0";
        switch (last_bit) {
            case '0':
                replacement = "1";
                if (bin.size() > 1) {
                    string prefix = decrementBin(bin.substr(0, bin.size() - 1), 1);
                    bin = prefix.append(replacement);
                } else {
//                    If you arrive at the left-most element, and it finds a '0' there, return the empty string,
//                    so the string size gets decreased.
                    return "";
                }
                break;
            case '1':
                replacement = "0";
                break;
            default:
                break;
        }
        bin.replace(bin.size() - 1, 1, replacement);
    }
    return bin;
}

/**
 * Converts a binary string to a hexadecimal string.
 * Partially inspired by user https://stackoverflow.com/users/335858/sergey-kalinichenko on the thread
 * https://stackoverflow.com/questions/19461478/convert-binary-bitset-to-hexadecimal-c
 * @param bin Length needs to be divisible by 4 to be able to be converted to hexadecimal. Since that is base 16 = 2^4.
 * @return The hexadecimal representation of the given binary string.
 */
string binToHex(const string& bin) {
    string hex_hext;
    int step_size = 4;
    debugPrint("bin", bin, false);
    for (int i = 0; i < bin.size(); i += step_size) {
        string hex_as_bin = bin.substr(i, step_size);
        bitset<4>set(hex_as_bin);
        stringstream res;
        res << hex << uppercase << set.to_ulong();
        hex_hext += res.str();
    }
    return hex_hext;
}

/**
 * Decreases the hexadecimal string by the given amount.
 * This method uses a string that represents all the hexadecimal characters in order.
 * So, it replaces the current character with the previous one if possible.
 * If that isn't possible,
 * then it will try to perform this operation on the hexadecimal string to the left of this character.
 * If there is no such string, it will return the empty string.
 * @param hex The hexadecimal string that needs to be decreased.
 * @param decrement The amount, the string needs to be decreased by.
 * @return A new hexadecimal string, decreased by the specified amount.
 * If the given decrement is larger than the number the hexadecimal string represents,
 * then it will return the empty string. It also does not keep the original size.
 * Namely, it will remove any trailing 0's.
 */
string decrementHex(string hex, unsigned int decrement) {
    for (int i = 0; i < decrement; i++) {
        char last_el = (char) tolower(hex[hex.size() - 1]);
        unsigned long idx_of_last = getHexChars().find(last_el);
        string replacement;
        if (idx_of_last != 0) {
            replacement = getHexChars()[idx_of_last - 1];
        } else {
            replacement = getHexChars()[getHexChars().size() - 1];
            if (hex.size() == 1) {
                return "";
            }
            hex = decrementHex(hex.substr(0, hex.size() - 1), 1).append(replacement);
        }
        hex.replace(hex.size() - 1, 1, replacement);
    }
    return hex;
}

/**
 * Increases the hexadecimal string by the given amount.
 * This method uses a string that represents all the hexadecimal characters in order.
 * So, it replaces the current character with the next one if possible.
 * If it isn't possible,
 * then it will try to perform this operation on the hexadecimal string to the left of this character.
 * If there is no such string, it will extend the string and then try it.
 * @param hex The hexadecimal string that needs to be increased.
 * @param decrement The amount, the string needs to be increased by.
 * @return A new hexadecimal string, increased by the specified amount. It does not keep the original size.
 * Namely, it will increase in size if overflow would happen otherwise.
 */
string incrementHex(string hex, int increment) {
    debugPrint("inc", increment, false);
    for (int i = 0; i < increment; i++) {
        debugPrint("hex", hex, false);
        char last_el = (char) tolower(hex[hex.size() - 1]);
        unsigned long idx_of_last = getHexChars().find(last_el);
        string replacement;
        if (idx_of_last != getHexChars().size() - 1) {
            replacement = getHexChars()[idx_of_last + 1];
        }
        else {
            replacement = getHexChars()[0];
            if (hex.size() == 1) {
//                Extend the string, so another increment is possible.
                hex = hex.insert(0, replacement);
            }
            hex = incrementHex(hex.substr(0, hex.size() - 1), 1).append(replacement);
        }
        hex.replace(hex.size() - 1, 1, replacement);
    }
    return hex;
}

/**
 * Adds both hexadecimals to each other.
 * It converts one hexadecimal into an integer and increments the other by that amount.
 * @param hex1 A hexadecimal string
 * @param hex2 A hexadecimal string
 * @return The outcome of hex1 + hex2.
 */
string hexAddition(string hex1, const string& hex2) {
    int hex2_as_int = stoi(hex2, nullptr, 16);
    debugPrint("hex2 as int", hex2_as_int, false);
    return incrementHex(std::move(hex1), hex2_as_int);
}

/**
 * Splits the given hexadecimal string into hextets and adds all these together.
 * @param hex A hexadecimal string
 * @return A hexidecimal string, not a hextet, because it could be overflowing. So, the overflow is kept.
 */
string hextetSum(const string& hex) {
    string hextet_sum = "0000";
//    A hextet uses 4 hexadecimal character, since hexadecimal is base 4 and a hextet consists of 16 bits.
    int step_size = 4;
    for (int i = 0; i < hex.size(); i += step_size) {
        string hextet = hex.substr(i, step_size);
        debugPrint("hextet", hextet, false);
        hextet_sum = hexAddition(hextet_sum, hextet);
        debugPrint("hextet_sum", hextet_sum, false);
    }
    return hextet_sum;
}

/**
 * Flips all of the hexadecimal characters. E.g. 'f' becomes '0', 'a' becomes '5', '7' becomes '8', etc.
 * @param hex A hexadecimal string
 * @return The given hexadecimal string, inverted.
 */
string invHex(const string& hex) {
    string hex_inv;

    for (auto &&el : hex) {
        unsigned int idx_of_el = getHexChars().find(el);
        hex_inv += getHexChars()[getHexChars().size() - 1 - idx_of_el];
    }
    debugPrint("hex_inv", hex_inv, false);
    return hex_inv;
}

/**
 * Converts the IP-address to a binary string. This is performed by splitting the address into integers,
 * converting those to binary and appending those.
 * @param ip The IP-address in regular form.
 * @return The binary representation of the IP-address.
 */
string ipToBin(const string& ip) {
    string result;

    vector<string> ip_bytes = split(ip, ".");
    vector<int> ip_as_ints = stringVecToIntVec(ip_bytes);

    for (int byte : ip_as_ints) {
        result += bitset<8>(byte).to_string();
    }
    debugPrint("ip_bin", result, false);
    return result;
}

/**
 * Calculates the correct checksum for the IPV4-header. For more info:
 * https://en.wikipedia.org/wiki/IPv4_header_checksum
 * @param ip_hdr The IPV4-header without the checksum filled in, or it does, I don't care, this method doesn't use it
 * @return The correct checksum.
 */
uint16_t ipChecksum(struct iphdr ip_hdr) {
//    Splits everything into hextets.
    string version = bitset<4>(ip_hdr.version).to_string();
    string ihl = bitset<4>(ip_hdr.ihl).to_string();
    string tos = bitset<8>(ip_hdr.tos).to_string();
    uint32_t version_IHL_DSCP_ECN_hextet = stoi(version + ihl + tos, nullptr, 2);

    uint32_t tot_len = ip_hdr.tot_len;
    uint32_t id = ip_hdr.id;
    uint32_t flag_frag_hext = ip_hdr.frag_off;

    string ttl = bitset<16>(ip_hdr.ttl).to_string();
    string protocol = bitset<16>(ip_hdr.protocol).to_string();
    uint32_t ttl_protocol_hextet = stoi(ttl + protocol, nullptr, 2);

    string src_ip = bitset<32>(ip_hdr.saddr).to_string();
    uint32_t src_ip_hext1 = stoi(src_ip.substr(0, 16), nullptr, 2);
    uint32_t src_ip_hext2 = stoi(src_ip.substr(16, 16), nullptr, 2);

    string dest_ip = bitset<32>(ip_hdr.daddr).to_string();
    uint32_t dest_ip_hext1 = stoi(dest_ip.substr(0, 16), nullptr, 2);
    uint32_t dest_ip_hext2 = stoi(dest_ip.substr(16, 16), nullptr, 2);

//    Add the hextets together
    uint32_t hext_sum = version_IHL_DSCP_ECN_hextet + tot_len + id + flag_frag_hext + ttl_protocol_hextet +
                        src_ip_hext1 + src_ip_hext2 + dest_ip_hext1 + dest_ip_hext2;
    debugPrint("h_sum", hext_sum, false);

//    Remove overflow
    hext_sum = removeShortOverflow(hext_sum);
    debugPrint("h_sum", hext_sum, false);

//    Invert
    uint16_t inv_hext = stoi(invBin(bitset<16>(hext_sum).to_string()), nullptr, 2);

//    Tada!
    return inv_hext;
}

/**
 * !!! THIS METHOD IS NOT WATERPROOF, BUT IT IS UNUSED FOR NOW, SO I DON'T CARE !!!
 * Reverse engineers the IPV4-header checksum calculation to create a custom ID, so the IPV4-header is valid.
 * For more info: https://en.wikipedia.org/wiki/IPv4_header_checksum
 * @param desiredChecksum This is the checksum we want our IPV4-header to have.
 * @param calcChecksum This is the checksum that was calculated by using the default fields.
 * @return The ID that the IPV4-header should have to get the desired checksum.
 * @see adaptedUDPSrcPort for a better method
 */
string createCorrectId(const string& desiredChecksum, const string& calcChecksum) {
//    !!! THIS METHOD IS NOT WATERPROOF, BUT IT IS UNUSED FOR NOW, SO I DON'T CARE !!!
    string id = "0000";
    string cal_checksum_hex = binToHex(calcChecksum);
    debugPrint("des_sc", desiredChecksum, false);

    while (desiredChecksum != cal_checksum_hex) {
        debugPrint("cal_cs", cal_checksum_hex, false);
        id = incrementHex(id, 1);
        cal_checksum_hex = incrementHex(cal_checksum_hex, 1);
    }
    return hexToBin(id);
//    !!! THIS METHOD IS NOT WATERPROOF, BUT IT IS UNUSED FOR NOW, SO I DON'T CARE !!!
}

/**
 * Converts the binary string to a character. Needless to say, this binary string should not exceed 8 bits (char size).
 * @param bin A binary string consisting of 8 bits.
 * @return The binary string converted into a char.
 */
char binToChar(const string& bin) {
    return (char) stoi(bin, nullptr, 2);
}

/**
 * Converts the binary string into a string of characters.
 * Needless to say, the length of the binary string must be divisible by 8, since a character consists of 8 bits.
 * @param bin A binary string, which length must be divisible by 8.
 * @return A string of chars.
 */
string binToCharString(const string& bin) {
    string chars;
    int step_size = 8;
    for (int i = 0; i < bin.size(); i += step_size) {
        string char_as_bin = bin.substr(i, step_size);
        chars += binToChar(char_as_bin);
    }
    return chars;
}

/**
 * Creation of the IPV4-header.
 * @param src_ip The source IP-address as a binary string.
 * @param dest_ip The source IP-address as a binary string.
 * @param flag Integer representation of the flags bitset of size 3.
 * @return A valid IPV4-header.
 */
struct iphdr createIPHeader(const string& src_ip, const string& dest_ip, unsigned int flag) {
    struct iphdr ip_hdr{};
//    Creation of all the header fields.

//    Version = 4, because IPV4
    unsigned int version = htons(4);
//    IHL = 5, because no options
    unsigned int ihl = htons(5);
//    DSCP = 0, because not necessary here
//    ECN = 0, because not necessary here
//    These fields are merged, since they are merged in the struct.
    uint8_t dscp_ecn = htons(0);
//    Total length = 28, because size of IP + UDP header = 20 bytes + 8 bytes, respectively
    uint16_t len_total = htons(28);
//    Identification = 0, because not necessary here
    uint16_t id = htons(0);
//    Flags = 0, because doesn't matter here
//    Fragment offset = 0, data is at regular position
//    These fields are merged, since they are merged in the struct.
    string flag_str = bitset<3>(flag).to_string();
    string frag_off = bitset<13>(0).to_string();
    uint16_t flag_frag = htons(stoi(flag_str + frag_off,nullptr, 2));
//    Time To Live = 250, so the packet won't easily get dropped on the way
    uint8_t ttl = htons(250);
//    Protocol = 17, because UDP
    uint8_t protocol = htons(17);
//    Header checksum = 0, so it won't be checked :)
    uint16_t ip_checksum = htons(0);

/* For th ip-addresses, stoll is used, because they can't always fit in a positive integer.
 * Since that uses 31 bits for the default 32 bit environment */

//    Source IP address
    debugPrint("src_ip", src_ip, false);
    uint32_t src_ip_int = htons(stoll(ipToBin(src_ip), nullptr, 2));
    debugPrint("src_ip_int", src_ip_int, false);
//    Destination IP address
    debugPrint("dest_ip", dest_ip, false);
    string dest_ip_str = ipToBin(dest_ip);
    debugPrint("d_ip_str", dest_ip_str, false);
    uint32_t dest_ip_int = htons(stoll(dest_ip_str, nullptr, 2));

//    Creation of the ip-header
    ip_hdr.version = version;
    ip_hdr.ihl = ihl;
    ip_hdr.tos = dscp_ecn;
    ip_hdr.tot_len = len_total;
    ip_hdr.id = id;
    ip_hdr.frag_off = flag_frag;
    ip_hdr.ttl = ttl;
    ip_hdr.protocol = protocol;
    ip_hdr.check = ip_checksum;
    ip_hdr.saddr = src_ip_int;
    ip_hdr.daddr = dest_ip_int;
    return ip_hdr;
}

/**
 * Flip the bits in the binary string.
 * @param bin A binary string.
 * @return The inverted binary string.
 */
string invBin(string bin) {
    string bin_inv;
    for (char & bit : bin) {
        if (bit == '0') {
            bit = '1';
        } else {
            bit = '0';
        }
        bin_inv += bit;
    }
    return bin_inv;
}

/**
 * Reverse engineers the UDP-header checksum calculation to create a different source port.
 * This way, a valid UDP-header can be created with a custom checksum. For more info:
 * https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header
 * @param udp_hdr The UDP-header which may or may not contain a source port already.
 * This method doesn't look at it anyways. It does however, need to contain the altered checksum already.
 * @param srcIP The source IP-address, which is used to create the IPV4 pseudo header.
 * Which, in turn, is used to do the UDP-header checksum calculation,
 * thus the reverse engineering of that same calculation.
 * @param destIP The IP-address of the destination, which is used to create the IPV4 pseudo header.
 * Which, in turn, is used to do the UDP-header checksum calculation,
 * thus the reverse engineering of that same calculation.
 * @return The variable that the source port should be set to, encountered for the checksum.
 */
uint16_t adaptedUDPSrcPort(udphdr *udp_hdr, const string& srcIP, const string& destIP) {
    uint16_t correct_UDP_src_port;

//    Creation of the pseudo header fields.

//    IP-addresses split up into two hextets each, since they both use 32 bits.
    string src_ip_bin = ipToBin(srcIP);
    debugPrint("sip bin", src_ip_bin, false);
    uint32_t src_ip_1 = stoi(src_ip_bin.substr(0, 16), nullptr, 2);
    uint32_t src_ip_2 = stoi(src_ip_bin.substr(16, 16), nullptr, 2);
    string dest_ip_bin = ipToBin(srcIP);
    debugPrint("dip bin", dest_ip_bin, false);
    uint32_t dest_ip_1 = stoi(dest_ip_bin.substr(0, 16), nullptr, 2);
    uint32_t dest_ip_2 = stoi(dest_ip_bin.substr(16, 16), nullptr, 2);
//    Protocol = 17, because UDP, the zero-strings are mandatory padding
    uint8_t protocol = 17;
//    Just a copy of the length in the udp header
    uint32_t udp_len = udp_hdr->len;

//    Maximum amount of bits in the new source port.
    int max_size = 16;
//    The maximum number a 2 byte unsigned integer can reach.
    auto max_short = (unsigned int) pow(2, max_size) - 1;

/* Now follows the process of reverse engineering the given checksum,
 * so we can edit the length-field in the UDP header to get ensure that the checksum is valid. */
    debugPrint("check", udp_hdr->check, false);
    unsigned int inv_check_sum = max_short - udp_hdr->check;
    debugPrint("Inv check sum", inv_check_sum, false);

//    Adding all the header fields.
    uint32_t header_sum = src_ip_1 + src_ip_2 + dest_ip_1 + dest_ip_2 + protocol + udp_len + udp_hdr->len +
            udp_hdr->dest;
    debugPrint("Hex hdr sum", header_sum, false);

//    The sum of the header fields, possibly has overflow. Make sure that it doesn't
    header_sum = removeShortOverflow(header_sum);
    debugPrint("Hex hdr sum no of", header_sum, false);

/* Ensures that the inverse check sum is larger than the header checksum.
 * Since that difference is the new source port. */
    if (header_sum > inv_check_sum) {
        inv_check_sum += max_short;
    }
    debugPrint("Hdr sum, bin", header_sum, false);
    debugPrint("corrected checksum", inv_check_sum, false);
    correct_UDP_src_port = inv_check_sum - header_sum;
    debugPrint("udp len, no pad", correct_UDP_src_port, false);
    return correct_UDP_src_port;
}

/**
 * Deals with overflow when the given integer exceeds 16 bits (cannot be converted into a hextet).
 * @param header_sum An integer that might need more than 16 bits. I.e., it cannot be stored into a hextet.
 * @return A hextet in integer format.
 */
uint16_t removeShortOverflow(uint32_t header_sum) {
    auto max_size = (unsigned int) pow(2, 16);
    debugPrint("hs int", header_sum, false);
    while (header_sum >= max_size) {
//        Integer division
        unsigned int overflow = header_sum / max_size;
        unsigned int remainder = header_sum % max_size;
        header_sum = remainder + overflow;
    }
    debugPrint("Hs, no overflow", header_sum, false);
    return header_sum;
}

/**
 * Finds the absolute difference between two binary strings.
 * @param bin1 A binary string
 * @param bin2 A binary string
 * @return The result of |bin1 - bin2|.
 */
string binDiff(string bin1, const string& bin2) {
/* Since this method only really works when one binary string is larger than or equal to the other.
 * The program switches the strings around. */
    if (!binLarger(bin2, bin1)) {
        string diff = "0";
        while (bin1 != bin2) {
            bin1 = decrementBin(bin1, 1);
            diff = incrementHex(diff, 1);
        }
        return hexToBin(diff);
    } else {
        return binDiff(bin2, bin1);
    }
}

/**
 * Finds which binary string is larger.
 * @return Whether the second binary string is larger than the first binary string.
 */
bool binLarger(string bin1, string bin2) {
    for (int i = 0; i < bin1.size(); i++) {
        char bit_1 = bin1[i];
        char bit_2 = bin2[i];
        if (bit_1 == bit_2) {
            continue;
        } else if (bit_1 < bit_2) {
//            bit_1 = 0 and bit_2 = 1
            return true;
        } else {
//            bit_1 = 1 and bit_2 = 0
            return false;
        }
    }
//    Then equal, so not larger
    return false;
}

/**
 * Creates a valid UDP-header with a custom checksum by changing the source port. For more information:
 * https://en.wikipedia.org/wiki/User_Datagram_Protocol
 * @param dest_port The port that needs to receive the payload.
 * @param checksum The custom checksum
 * @param src_ip Used to create the IPV4 pseudo header for checksum calculation.
 * @param dest_ip Used to create the IPV4 pseudo header for checksum calculation.
 * @return A valid UDP-header, with a custom checksum and a changed source port.
 */
struct udphdr createUDPHeader(int dest_port, const string& checksum, const string& src_ip,
                            const string& dest_ip) {
    struct udphdr udp_hdr{};
//    Creation of the header fields
//    Source port = 0, will be changed later, is only here for a better overview
    uint16_t src = htons(0);
//    Destination port
    uint16_t dest = htons(dest_port);
//    Length = 8, because the UDP-header is 8 bytes long
    uint16_t len = htons(8);
//    Checksum
    debugPrint("check, pre-stoi", checksum, false);
    uint16_t check = htons(stoi(checksum, nullptr, 16));
    debugPrint("check, post-stoi", check, false);

//    Partial creation of the UDP header
    udp_hdr.dest = dest;
    udp_hdr.len = len;
    udp_hdr.check = check;

//    Correct the source port field, because we want a custom checksum
//    src = htons(adaptedUDPSrcPort(udp_hdr, src_ip, dest_ip));

//    Create the remainder of the header
    udp_hdr.source = src;
    return udp_hdr;
}

const char * createHeaders(const string &newSrcIP, const string &destIP, unsigned int flag, const string &newUDPChecksum,
                           int port) {
    return nullptr;
}

/**
 * Handles some incoming messages or lets other handlers handle them.
 * @param openPorts The open ports of the given IP-address. These are the ports we need to send special messages to.
 * @param sock The socket that the program will send packets over.
 * @param buffer The buffer containing the message the program wants to send for now.
 * @param destIP The location of the server that should receive the messages.
 */
void messageHandler(const vector<int>& openPorts, int sock, char *buffer, const string& destIP) {
/* This is the port we need to send the comma seperated list of secret ports to.
 * Set to -1, to detect that this port wasn't picked up. */
    int oracle_port = -1;

//    The hidden ports will be stored in here.
    vector<string> secret_ports;
//    The secret message
    string secret_msg;

// This is used for when this program cannot solve the puzzle yet.
    if (hardCodeHiddenPorts) {
        secret_ports.emplace_back("4014");
        secret_msg = "Hey you, you???re finally awake. You were trying to cross the border right? "
                     "Walked right into that Imperial ambush same as us and that thief over there.";
    }

/* These are some key-characters for determining what message was sent to find what to respond.
 * These characters, correspond to the first character in the given message. */

/* This character corresponds to the port that wants to receive a comma separated list, the oracle port.
 * If this is done correctly, another comma separated list is returned.
 * Which contain the ports that need to be knocked on in that order to get the secret message.
 * Knocking is just sending an arbitrary message, such as "Hey port!". */
    const char keyChar1 = 'I';

/* This character corresponds to the port that wants to receive the message of the form "$group_#$",
 * where # is the group number, in this case that is 47. This port will be called the 'checksum port'.
 * If this is done correctly, some information is given about the next message to send.
 * It contains the information about the ip- and udp-headers that need to be constructed and sent as a payload.
 * This message says that we need to create a valid ipv4 header, where the source ip is changed.
 * This altered ip is given in the message.
 * Another thing that the message tells us to do,
 * is to send a valid UDP-header after the IPV4 header in the payload where the UDP checksum is changed.
 * This specific checksum is given in the message as well.
 * To extract this information, string parsing is done by taking a substring of the message at a certain index.
 * Since the information always starts at the same indices.
 * Alternatively, one can extract the last 6 bytes to find this info.
 * Where the first 2 bytes, denote the checksum and the last 4 bytes represent the new source ip-address. */
    const char keyChar2 = 'S';

/* This character corresponds to the port that,
 * similarly to the message that the corresponding port of the previously mentioned character wanted to receive,
 * wants to receive the message of the form "$group_#$", where # is the group number, in this case that is 47.
 * This port will be called the 'evil port'.
 * However, the evil-bit needs to be set to 1 in the actual ip-header (so not sending the IPV4-header as a payload).
 * The evil-bit is one of the flags (the first) in the IPV4-header that is usually reserved to be 0.
 * To accomplish this, one must use a raw socket, so the headers can be changed. */
    const char keyChar3 = 'T';

/* This character corresponds to the port that we can do string parsing on to find one of the hidden ports,
 * that need to be in the comma separated list that the oracle wants to receive.
 * This port will be called the 'parsing port'.
 * This hidden port is always 4 digits long and has a period after it, which is the end of the message.
 * I.e., the hidden port can be found in msg.substring(len(msg) - 5, len(msg) - 1),
 * where the second parameter is the ending index, which is exclusive. */
    const char keyChar4 = 'M';

    for (auto&& open_port : openPorts) {
/* Used for testing msg where we put custom headers in the payload.
 * Should not be run during the final version. */
        if (testCustomHeader and open_port != 4097) {
            continue;
        }
        string response = sendAndReceive(sock, buffer, destIP, open_port);

//        Finds out what to do with the message and the port.
        char response_start = response[0];
        switch (response_start) {
            case (keyChar1): {
//            This is the oracle port.
                oracle_port = open_port;
                break;
            }
            case (keyChar2): {
//            This is the checksum port.
                response = checksumPortHandler(sock, destIP, open_port);
                break;
            }
            case (keyChar3): {
//            This is the evil port.
                evilPortHandler(sock, destIP, open_port);
                break;
            }
            case (keyChar4): {
//            This is the parsing port.
                string secret_port = response.substr(response.size() - 5, 4);
                secret_ports.push_back(secret_port);
                break;
            }
            default: {
//                This should not be possible.
                break;
            }
        }
    }
    string response = oraclePortHandler(sock, secret_ports, destIP, oracle_port, secret_msg);
}

/**
 * Sends the group number to the checksum port and forwards its response to checksumPortHandler2
 * @param sock The socket it uses to send the data.
 * @param destIP The IP-address of the destination.
 * @param port The checksum port.
 * @return TODO: Figure out what to return here.
 */
string checksumPortHandler(int sock, const string &destIP, const int &port) {
    string parsed_string;
    char buff_group_msg[1400];
    strcpy(buff_group_msg, groupNumber);
    string response = sendAndReceive(sock, buff_group_msg, destIP, port);

    if (!hardCodeHiddenPorts) {
        response = checksumPortHandler2(sock, response, destIP, port);
    }
    return parsed_string;
}

/**
 * Uses the information gathered in checksumPortHandler and does some string parsing here.
 * It passes this information to checksumPortHandler3.
 * @param sock The socket it uses to send the data.
 * @param destIP The IP-address of the destination.
 * @param port The checksum port.
 * @return TODO: Figure out what to return here.
 * If the program did not send the previous message correctly, then it will return the empty string.
 */
string checksumPortHandler2(int sock, string response, const string& destIP, int port) {
/* This character corresponds to successfully sending the group number, correctly formatted, to the checksum port.
 * To summarise what has been stated previously for what the next step is.
 * The program needs to send a changed IPV4- and UDP-header as a payload.
 * The previous response contains the information as to change which header fields and how. */
    char keyChar2_2 = 'H';

    string parsed_string;
    if (response[0] != keyChar2_2) {
        return parsed_string;
    }
    string new_UDP_checksum;
    string new_src_ip;
//    The previously mentioned values always start at the same index in the message.
    int checksumStartIdx = 146;
    int srcIpStartIdx = 186;

//    Gets the new UDP checksum and the new source ip for the next msg from the response

//    Since the checksum is in hexadecimal form and is one hextet long, it is always of length 4.
    int checksum_size = 4;
    for (int i = checksumStartIdx; i < checksumStartIdx + 4; i++) {
        new_UDP_checksum += response[i];
    }
    int i = srcIpStartIdx;
    char curr_char = response[i];
//    The given IP-address consists of digits separated by periods.
//    The distance between the periods can differ.
    while (isdigit(curr_char) || curr_char == '.') {
        new_src_ip += curr_char;
        i++;
        curr_char = response[i];
    }
    debugPrint("new UDP checksum", new_UDP_checksum, false);
    debugPrint("new src ip", new_src_ip, false);

    response = checksumPortHandler3(sock, destIP, port, new_UDP_checksum, new_src_ip);

    return parsed_string;
}

/**
 * Creates valid IPV4- and UDP-headers and sends them as a payload.
 * @param sock The socket used for sending.
 * @param destIP The IP-address of the destination.
 * @param port The port to send it to, the checksum port.
 * @param newUDPChecksum The checksum that should be as the UDP-header
 * @param newSrcIp The changed source IP-address
 * @return TODO: Figure out what to return here.
 */
string checksumPortHandler3(int sock, const string &destIP, int port, const string& newUDPChecksum,
                            const string& newSrcIp) {
//    Creation of the buffer
    char buff_special_msg[1400];

    unsigned int flag = 0;

    strcpy(buff_special_msg, createHeaders(newSrcIp, destIP, flag, newUDPChecksum, port));

//    Letting separate functions did not work. So unfortunately we need one long, ugly function instead.
//    Creating the headers that go into the payload.

//    Creation of IPV4-header
    auto* ip_hdr = (struct iphdr*) (buff_special_msg);

/* Creation of all the header fields.
 * For more information about this, consult https://en.wikipedia.org/wiki/IPv4#Header
 * These are all converted to network byte order. Because, well, they are being sent over a network. */

//    Version = 4, because we are creating an IPV4-header
    unsigned int version = htons(4);
/* IHL = 5, because we are leaving the options field empty.
 * And 5 hextets is the size of the IPV4 header without them. */
    unsigned int ihl = htons(5);

//    DSCP = 0, because not necessary here.
    string dscp = bitset<6>(0).to_string();
//    ECN = 0, because not necessary here.
    string ecn = bitset<2>(0).to_string();
//    DSCP and ECN are merged for the iphdr struct.
    uint8_t dscp_ecn = htons(stoi(dscp + ecn, nullptr, 2));

/* Total length = 28, because len(ip_header) + len(udp_header) = 20 bytes + 8 bytes respectively.
 * And the program is not sending any extra data. */
    uint16_t len_total = htons(28);
//    Identification = 0, because not necessary here
    uint16_t id = htons(0);

//    Flags = 0, because they don't matter here
    string flag_str = bitset<3>(0).to_string();
//    Fragment offset = 0, since data is at regular position
    string frag_off = bitset<13>(0).to_string();
//    Flags and fragment offset are merged for iphdr struct.
    uint16_t flag_frag = htons(stoi(flag_str + frag_off, nullptr, 2));

//    Time To Live = 250, so we can have a decent TTL
    uint8_t ttl = htons(250);
//    Protocol = 17, because we're using a UDP-header
    uint8_t protocol = htons(17);
//    Header checksum = 0, so it won't be checked
    uint16_t ip_checksum = htons(0);

/* For the ip-addresses, stoll is used, instead of stoi, because they can't fit in a positive integer.
 * Since that uses 31 bits for the default 32 bit environment. Since the first bit denotes the sign of the integer. */
//    Source IP address
    debugPrint("newSrcIp", newSrcIp, false);
    string src_ip_str = ipToBin(newSrcIp);
    debugPrint("s_ip_str", src_ip_str, false);
    uint32_t src_ip_int = htons(stoll(src_ip_str, nullptr, 2));
    debugPrint("src_ip_int", src_ip_int, false);
//    Destination IP address
    debugPrint("destIP", destIP, false);
    string dest_ip_str = ipToBin(destIP);
    debugPrint("d_ip_str", dest_ip_str, false);
    uint32_t dest_ip_int = htons(stoll(dest_ip_str, nullptr, 2));

//    Creation of the iphdr struct.
    ip_hdr->version = version;
    ip_hdr->ihl = ihl;
    ip_hdr->tos = dscp_ecn;
    ip_hdr->tot_len = len_total;
    ip_hdr->id = id;
    ip_hdr->frag_off = flag_frag;
    ip_hdr->ttl = ttl;
    ip_hdr->protocol = protocol;
    ip_hdr->check = ip_checksum;
    ip_hdr->saddr = src_ip_int;
    ip_hdr->daddr = dest_ip_int;
    debugPrint("buffer", buff_special_msg, false);

//    Creation of UDP-header
    auto* udp_hdr = (struct udphdr*)(buff_special_msg + sizeof(*ip_hdr));

//    Creation of the UDP-header fields

//    Source port = 0, will be changed later, is just here to show that this is the order of the header fields.
    uint16_t src = htons(0);
//    Destination port
    uint16_t dest = htons(port);
//    Length = 8, because the length of the UDP header is 8 bytes, and the program is not sending any extra data.
    uint16_t len = htons(8);
//    Checksum
    debugPrint("check, pre-stoi", newUDPChecksum, false);
    uint16_t check = htons(stoi(newUDPChecksum, nullptr, 16));
    debugPrint("check, post-stoi", check, false);

//    Partial creation of the UDP-header
    udp_hdr->dest = dest;
    udp_hdr->len = len;
    udp_hdr->check = check;

//    Correct the source port field, because we want a custom checksum
    src = htons(adaptedUDPSrcPort(udp_hdr, newSrcIp, destIP));

//    Create the remainder of the header
    udp_hdr->source = src;

    debugPrint("iphdr size", sizeof(*ip_hdr), false);
    debugPrint("udphdr size", sizeof(*udp_hdr), false);

//    Printing ip header info
    debugPrint("iphdr ver", ip_hdr->version, false);
    debugPrint("iphdr ihl", ip_hdr->ihl, false);
    debugPrint("iphdr tos", ip_hdr->tos, false);
    debugPrint("iphdr len", ip_hdr->tot_len, false);
    debugPrint("iphdr id", ip_hdr->id, false);
    debugPrint("iphdr fo", ip_hdr->frag_off, false);
    debugPrint("iphdr ttl", ip_hdr->ttl, false);
    debugPrint("iphdr protocol", ip_hdr->protocol, false);
    debugPrint("iphdr check", ip_hdr->check, false);
    debugPrint("iphdr sad", ip_hdr->saddr, false);
    debugPrint("iphdr dad", ip_hdr->daddr, false);

//    Printing udp header info
    debugPrint("udphdr src", udp_hdr->source, false);
    debugPrint("udphdr dest", udp_hdr->dest, false);
    debugPrint("udphdr len", udp_hdr->len, false);
    debugPrint("udphdr check", udp_hdr->check, false);

//    TODO: Remove this commented out code in final version.
    strcpy(buff_special_msg, "$group_47$");
//    memcpy(buff_special_msg, &ip_hdr, sizeof(*ip_hdr));
//    Make the udp header appear after the ip header in the buffer
//    memcpy(buff_special_msg + sizeof(*ip_hdr), &udp_hdr, sizeof(*udp_hdr));
    debugPrint("buffer", buff_special_msg, false);

    string response = sendAndReceive(sock, buff_special_msg, destIP, port);
//    TODO: Change this to do something with the response.
//    secret_ports.push_back(response);
    return response;
}


/**
 * Creates valid IPV4- and UDP-headers and sends them as a payload.
 * @param sock The socket used for sending.
 * @param destIP The IP-address of the destination.
 * @param port The port to send it to.
 * @return TODO: Figure out what to return here.
 */
void evilPortHandler(int sock, const string &destIP, const int &port) {

        const char* special_msg = "group_47$";
    char buff_special_msg[1400];
    // create raw socket
    int sock_raw = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock_raw == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *data , *pseudogram;
    //zero out the packet buffer
    memset (datagram, 0, 4096);
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram; //createIPHeader(4)
    //UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in sin;

    // Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strcpy(data , "$group_47$");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    // Id of this packet
    iph->id = htonl (54321);
    // set evil bit
    iph->frag_off |= htons(IP_EVIL);
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    // Spoof the source ip address
    iph->saddr = inet_addr ( source_ip );
    // put destination IP address
    iph->daddr = inet_addr(destIP.c_str());

    // UDP header
    udph->source = htons (6666);
    udph->dest = htons (port);
    // tcp header size
    udph->len = htons(8 + strlen(data));
    udph->check = 0;

    // Send the packet
    if (sendto(sock_raw, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror("sendto failed");
    }
        // Data sent successfully
    else
    {
        // create UDP receive socket
        int recv_sock = socket(AF_INET, SOCK_DGRAM, 17);
        // set socket to same port
        const char *opt;
        opt = "eth0";
        int len = strnlen(opt, IFNAMSIZ);   // was const not int
        setsockopt(recv_sock, 17, SO_BINDTODEVICE, opt, len);
        char recv_buff[2000];
        // Detects whether anything is received.
        struct sockaddr_in receive_address{};
        socklen_t address_len = sizeof(receive_address);
        recvfrom(recv_sock, recv_buff, sizeof(recv_buff), 0,(struct sockaddr*)&receive_address, &address_len);
        debugPrint("sender ip", inet_ntoa(receive_address.sin_addr), true);
        debugPrint("sender port", ntohs(receive_address.sin_port), true);
        debugPrint("resp", recv_buff, true);
    }
}



/**
 * Sends the hidden ports in a comma seperated list to the oracle port
 * and passes that response on to oraclePortHandler2.
 * @param sock The socket that sends the data.
 * @param secret_ports The hidden ports
 * @param destIP The IP-address of the destination
 * @param port The port to send the info to
 * @param secretMsg The secret message, which is needed later.
 * @return TODO: Figure out what to return here.
 */
string oraclePortHandler(int sock, vector<string> secret_ports, const string &destIP, int port, const string& secretMsg){
//    Creating the comma separated list to send to the port.
    string secret_ports_csl;
    for (int i = 0; i < secret_ports.size(); i++) {
        secret_ports_csl += secret_ports[i];
        if (i < secret_ports.size() - 1) {
            secret_ports_csl += ", ";
        }
    }
    char buff_special_msg[1400];
    strcpy(buff_special_msg, secret_ports_csl.c_str());
    string response = sendAndReceive(sock, buff_special_msg, destIP, port);
    return oraclePortHandler2(sock, destIP, response, secretMsg);
}

/**
 * Parses the response of the previous handler and knocks on the hidden ports.
 * This response is sent to oraclePortHandler3;
 * @param sock The socket it uses to send the data.
 * @param destIP The IP-address of the destination.
 * @param previous_response The response that the previous handler received.
 * @param secretMsg The secret message that needs to be sent to each of the hidden ports as a knock.
 * @return TODO: Figure out what to return here.
 * If the program did not send the previous message correctly, then it will return the empty string.
 */
string oraclePortHandler2(int sock, const string &destIP, string previous_response, const string& secretMsg) {
/* This character corresponds to successfully sending the comma seperated list, correctly formatted, to the oracle port.
 * To summarise what has been stated previously for what the next step is.
 * The port will send the program a different comma seperated list.
 * The program needs to knock on these ports in the correct order to get the secret message.
 * When it has done so, the final port will respond with "You have knocked. You may enter". */
    char key_char1_2 = '4';
    if (previous_response[0] == key_char1_2) {
//      Conversion from the received comma separated list to a vector of ports.
        debugPrint("prev response", previous_response, false);
        vector<int> port_knox = stringVecToIntVec(split(previous_response, ","));
        char buff[1400];
        strcpy(buff, secretMsg.c_str());
        vector<string> responses = sendAndReceive(sock, buff, destIP, port_knox);

//      Prints out the response we got from the server
        cout << "The server responded:" << endl;
        for (auto&& response : responses) {
            cout << response << endl;
        }
        return oraclePortHandler3(sock, destIP, responses, port_knox, secretMsg);
    }
    return "";
}

/**
 * This function enters the hidden port.
 * @param sock The socket it uses to send the data.
 * @param destIp The IP-address of the destination.
 * @param responses All the responses from each port they got from the previous handler.
 * Only the last response is valuable.
 * @param portKnox The ports it sent the previous data to.
 * @return TODO: Figure out what to return here.
 * If the program did not send the previous message correctly, then it will return the empty string.
 */
string oraclePortHandler3(int sock, const string &destIp, vector<string> responses, const vector<int> &portKnox,
                          const string& secretMsg) {
/* This character corresponds to successfully sending the port knocks in the correct order.
 * When done so, the final hidden port will send the message starting with this character.
 * Namely, this message is: "You have knocked. You may enter"*/
    char key_char1_3 = 'Y';

    int final_hidden_port = portKnox[portKnox.size() - 1];
    if (responses[responses.size() - 1][0] == key_char1_3) {
        char buff[1400];
        strcpy(buff, secretMsg.c_str());
        sendAndReceive(sock, buff, destIp, final_hidden_port);
//        TODO: implement this
    }
    return "";
}



int main(int argc, char *argv[]) {
    switch (programToRun) {
        case scanner:
            runScanner(argc, argv);
            break;
        case puzzleSolver:
            runPuzzle(argc, argv);
            break;
        default:
            break;
    }
}