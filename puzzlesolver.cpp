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
#include <bitset>
#include <cmath>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

int NO_OF_RETRIES = 20;
//    In milliseconds
int TIMEOUT = 400;
// These always start at the same index in the message.
int CHECKSUM_START_IND = 146;
int SRC_IP_START_IND = 186;
// Used for testing
bool DEBUG = false;
bool HARD_CODED_PORTS = true;
bool TEST_CUSTOM_HDR = false;

void sendMessage(std::vector<int> open_ports, int sock, char *buffer, std::string dest_ip);


bool binHectetIsLarger(std::string basicString, std::string basicString1);

std::string binDiff(std::string basicString, const std::string& basicString1);

int main(int argc, char *argv[]) {
//    Default parameters which might be changed depending on how many arguments are given.
//    Default ip-address
    std::string dest_ip = "130.208.242.120";
//    The secret ports
    std::vector<int> open_ports;

//    The UDP socket
    int sock = socket_creation();
    struct sockaddr_in destaddr = sock_opts(sock, dest_ip, TIMEOUT);

//    The msg sent to the port
    char buffer[1400];
    int buff_len = sizeof(buffer);
    strcpy(buffer, "Hey Port");
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
        if (HARD_CODED_PORTS) {
            open_ports.push_back(4042);
            open_ports.push_back(4097);
            open_ports.push_back(4098);
            open_ports.push_back(4099);
        } else {
            open_ports = find_open_ports(destaddr, from, to, sock, buffer, buff_len, NO_OF_RETRIES);
        }
    }

    sendMessage(open_ports, sock, buffer, dest_ip);
}


void debugPrint(const std::string &arg_name, const std::string &arg, bool debug_override) {
    if (DEBUG || debug_override) {
        std::cout << arg_name + "=" << arg << "\n";
    }
}


void debugPrint(const std::string &arg_name, unsigned long arg, bool debug_override) {
    debugPrint(arg_name, std::to_string(arg), debug_override);
}


std::string hexToBin(const std::string& hex) {
    std::string bin;
    debugPrint("hex", hex, false);
    for (char single_hex : hex) {
        switch (single_hex) {
            case '0':
                bin += "0000";
                break;
            case '1':
                bin += "0001";
                break;
            case '2':
                bin += "0010";
                break;
            case '3':
                bin += "0011";
                break;
            case '4':
                bin += "0100";
                break;
            case '5':
                bin += "0101";
                break;
            case '6':
                bin += "0110";
                break;
            case '7':
                bin += "0111";
                break;
            case '8':
                bin += "1000";
                break;
            case '9':
                bin += "1001";
                break;
            case 'A':
            case 'a':
                bin += "1010";
                break;
            case 'B':
            case 'b':
                bin += "1011";
                break;
            case 'C':
            case 'c':
                bin += "1100";
                break;
            case 'D':
            case 'd':
                bin += "1101";
                break;
            case 'E':
            case 'e':
                bin += "1110";
                break;
            case 'F':
            case 'f':
                bin += "1111";
                break;
            default:
                break;
        }
    }
    debugPrint("bin", bin, false);
    return bin;
}


std::string decrementBin(std::string bin, int decrement) {
    for (int i = 0; i < decrement; i++) {
        char last_bit = bin.at(bin.size() - 1);
        std::string replacement = "0";
        switch (last_bit) {
            case '0':
                replacement = "1";
                if (bin.size() > 1) {
                    bin = decrementBin(bin.substr(0, bin.size() - 1), 1) + replacement;
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


std::string incrementHex(std::string hex, int increment) {
    for (int i = 0; i < increment; i++) {
        char last_hex = hex.at(hex.size() - 1);
        std::string replacement = "0";
        switch (last_hex) {
            case '0':
                replacement = "1";
                break;
            case '1':
                replacement = "2";
                break;
            case '2':
                replacement = "3";
                break;
            case '3':
                replacement = "4";
                break;
            case '4':
                replacement = "5";
                break;
            case '5':
                replacement = "6";
                break;
            case '6':
                replacement = "7";
                break;
            case '7':
                replacement = "8";
                break;
            case '8':
                replacement = "9";
                break;
            case '9':
                replacement = "a";
                break;
            case 'A':
            case 'a':
                replacement = "b";
                break;
            case 'B':
            case 'b':
                replacement = "c";
                break;
            case 'C':
            case 'c':
                replacement = "d";
                break;
            case 'D':
            case 'd':
                replacement = "e";
                break;
            case 'E':
            case 'e':
                replacement = "f";
                break;
            case 'F':
            case 'f':
                replacement = "0";
                if (hex.size() == 1) {
                    hex = "0" + hex;
                }
                hex = incrementHex(hex.substr(0, strlen(hex.c_str()) - 1), 1) + replacement;
                break;
            default:
                break;
        }
        hex.replace(strlen(hex.c_str()) - 1, 1, replacement);
    }
    return hex;
}


std::string binToHex(const std::string& bin_hect) {
    std::string hex_hect;
    int step_size = 4;
    debugPrint("bin_hect", bin_hect, false);
    for (int i = 0; i < bin_hect.size(); i += step_size) {
        std::string hex_as_bin = bin_hect.substr(i, step_size);
        std::string hex = "0";
        debugPrint("hex_as_bin", hex_as_bin, false);
        for (int j = 0; j < hex_as_bin.size(); j++) {
            char bit = hex_as_bin[j];
            if (hex_as_bin[j] == '1') {
                int increment = (int) pow(2, hex_as_bin.size() - j - 1);
                hex = incrementHex(hex, increment);
            }
        }
        debugPrint("hex", hex, false);
        hex_hect += hex;
    }
    return hex_hect;
}


std::string binHectToHexHect(const std::string& bin) {
    std::string hex;
    int step_size = 16;
    debugPrint("bin", bin, false);
    for (int i = 0; i < bin.size(); i += step_size) {
        std::string bin_hect = bin.substr(i, step_size);
        debugPrint("bin_sz", bin.size(), false);
        std::string hex_hect = binToHex(bin_hect);
        debugPrint("bin_hect", bin_hect, false);
        debugPrint("hex_hect", hex_hect, false);
        hex += hex_hect;
    }
    return hex;
}


std::string decrementHex(std::string hex, int decrement) {
    for (int i = 0; i < decrement; i++) {
        char last_hex = hex.at(hex.size() - 1);
        std::string replacement = "0";
        switch (last_hex) {
            case '0':
                replacement = "f";
                if (hex.size() > 1) {
                    hex = decrementHex(hex.substr(0, strlen(hex.c_str()) - 1), 1) + replacement;
                }
                break;
            case '1':
                replacement = "0";
                break;
            case '2':
                replacement = "1";
                break;
            case '3':
                replacement = "2";
                break;
            case '4':
                replacement = "3";
                break;
            case '5':
                replacement = "4";
                break;
            case '6':
                replacement = "5";
                break;
            case '7':
                replacement = "6";
                break;
            case '8':
                replacement = "7";
                break;
            case '9':
                replacement = "8";
                break;
            case 'A':
            case 'a':
                replacement = "9";
                break;
            case 'B':
            case 'b':
                replacement = "a";
                break;
            case 'C':
            case 'c':
                replacement = "b";
                break;
            case 'D':
            case 'd':
                replacement = "c";
                break;
            case 'E':
            case 'e':
                replacement = "d";
                break;
            case 'F':
            case 'f':
                replacement = "e";
                break;
            default:
                break;
        }
        hex.replace(strlen(hex.c_str()) - 1, 1, replacement);
    }
    return hex;
}


std::string addHectets(std::string hectet1, std::string hectet2) {
    std::string zero_hect = "0000";

    while (hectet2 != zero_hect) {
        hectet1 = incrementHex(hectet1, 1);
        hectet2 = decrementHex(hectet2, 1);
    }

    return hectet1;
}


std::string hectetSum(std::string hex) {
    std::string hectet_sum = "0000";

    while (!hex.empty()) {
        debugPrint("hex", hex, false);

        std::string hectet = hex.substr(0, 4);
        debugPrint("hectet", hectet, false);

        hex = hex.substr(4, hex.size() - 4);
        hectet_sum = addHectets(hectet_sum, hectet);
        debugPrint("hectet_sum", hectet_sum, false);
    }
    return hectet_sum;
}


std::string invHex(const std::string& hect) {
    std::string inv_hect;

    for (auto &&hex : hect) {
        switch(hex) {
            case '0':
                inv_hect += "f";
                break;
            case '1':
                inv_hect += "e";
                break;
            case '2':
                inv_hect += "d";
                break;
            case '3':
                inv_hect += "c";
                break;
            case '4':
                inv_hect += "b";
                break;
            case '5':
                inv_hect += "a";
                break;
            case '6':
                inv_hect += "9";
                break;
            case '7':
                inv_hect += "8";
                break;
            case '8':
                inv_hect += "7";
                break;
            case '9':
                inv_hect += "6";
                break;
            case 'A':
            case 'a':
                inv_hect += "5";
                break;
            case 'B':
            case 'b':
                inv_hect += "4";
                break;
            case 'C':
            case 'c':
                inv_hect += "3";
                break;
            case 'D':
            case 'd':
                inv_hect += "2";
                break;
            case 'E':
            case 'e':
                inv_hect += "1";
                break;
            case 'F':
            case 'f':
                inv_hect += "0";
                break;
            default:
                break;
        }
    }
    debugPrint("inv_hect", inv_hect, false);
    return inv_hect;
}


std::string ipToBin(const std::string& ip) {
    debugPrint("ip", ip, false);
    std::string result;

    std::string delimiter = ".";

    unsigned long prev_ind_occ = 0;
    unsigned long ind_occ = ip.find(delimiter);
    while (ind_occ != std::string::npos) {
        unsigned long ind_diff = ind_occ - prev_ind_occ;
        char *prefix = new char[ind_diff + 1];
        strcpy(prefix, ip.substr(prev_ind_occ, ind_diff).c_str());
        int ip_addr_part = char_pointer_to_int(prefix);
        result += std::bitset<8>(ip_addr_part).to_string();
        prev_ind_occ = ind_occ + 1;
        ind_occ = ip.find(delimiter, prev_ind_occ);
    }
    unsigned long ind_diff = ip.size() - prev_ind_occ;
    char *prefix = new char[ind_diff + 1];
    strcpy(prefix, ip.substr(prev_ind_occ).c_str());
    int ip_addr_part = char_pointer_to_int(prefix);
    result += std::bitset<8>(ip_addr_part).to_string();

    debugPrint("ip_bin", result, false);
    return result;
}


std::string ipChecksum(const std::string& ip_header_no_check) {
    std::string ip_h_nc_hex = binHectToHexHect(ip_header_no_check);
    debugPrint("iphnc_hex", ip_h_nc_hex, false);

    std::string hect_sum = hectetSum(ip_h_nc_hex);
    debugPrint("h_sum", hect_sum, false);

    std::string threeHexZero = "000";
    while (hect_sum.size() > 4) {
        hect_sum = hectetSum(threeHexZero + hect_sum);
    }
    debugPrint("h_sum", hect_sum, false);

    std::string inv_hect = invHex(hect_sum);

    return hexToBin(inv_hect);
}


std::string createCorrectId(const std::string& desired_checksum, const std::string& calc_checksum) {
    std::string id = "0000";
    std::string cal_checksum_hex = binToHex(calc_checksum);
    debugPrint("des_sc", desired_checksum, false);

    while (desired_checksum != cal_checksum_hex) {
        debugPrint("cal_cs", cal_checksum_hex, false);
        id = incrementHex(id, 1);
        cal_checksum_hex = incrementHex(cal_checksum_hex, 1);
    }
    return hexToBin(id);
}


int binToInt(const std::string& bin) {
    int bin_as_int = 0;
    for (int j = 0; j < bin.size(); j++) {
        char bit = bin[j];
        if (bin[j] == '1') {
            int increment = (int) pow(2, bin.size() - j - 1);
            bin_as_int += increment;
        }
    }
    return bin_as_int;
}


char binToChar(const std::string& bin) {
    return (char) binToInt(bin);
}


std::string binToChars(const std::string& bin) {
    std::string chars;
    int step_size = 8;
    for (int i = 0; i < bin.size(); i += step_size) {
        std::string char_as_bin = bin.substr(i, step_size);
        chars += binToChar(char_as_bin);
    }
    return chars;
}


std::string createIPHeader(const std::string& src_ip, const std::string& dest_ip) {
    std::string ip_header;
//    Creation of all the header fields.
//    Version = 4, because ipv4
    std::string version = std::bitset<4>(4).to_string();
//    IHL = 5, because no options
    std::string ihl = std::bitset<4>(5).to_string();
//    DSCP = 0, because not necessary here
    std::string dscp = std::bitset<6>(0).to_string();
//    ECN = 0, because not necessary here
    std::string ecn = std::bitset<2>(0).to_string();
//    Total length = 28, because IP + UDP header
    std::string len_total = std::bitset<16>(28).to_string();
//    Identification = 0, because not necessary here
    std::string id = std::bitset<16>(0).to_string();
//    Flags = 0, because doesn't matter here
    std::string flags = std::bitset<3>(0).to_string();
//    Fragment offset = 0, data is at regular position
    std::string frag_off = std::bitset<13>(0).to_string();
//    TTL = 250 so we can have a decent TTL
    std::string ttl = std::bitset<8>(250).to_string();
//    Protocol = 17, because UDP
    std::string protocol = std::bitset<8>(17).to_string();
//    Header checksum, set to 0 for default, will be changed later
    std::string ip_checksum = std::bitset<16>(0).to_string();
//    Source IP address
    std::string src_ip_bin = ipToBin(src_ip);
//    Destination IP address
    std::string dest_ip_bin = ipToBin(dest_ip);

//    Partly creation of the ip-header
    ip_header += version;
    ip_header += ihl;
    ip_header += dscp;
    ip_header += ecn;
    ip_header += len_total;
    ip_header += id;
    ip_header += flags;
    ip_header += frag_off;
    ip_header += ttl;
    ip_header += protocol;

//    Merge the addresses into one string for readability
    std::string ip_addresses;
    ip_addresses += src_ip_bin;
    ip_addresses += dest_ip_bin;

//    Calculate the correct ip-header checksum
    ip_checksum = ipChecksum(ip_header + ip_addresses);

//    Merge the ip-header fields
    ip_header += ip_checksum;
    ip_header += ip_addresses;
    return ip_header;
}


std::string invBin(std::string bin) {
    std::string bin_inv;
    for (char & bit : bin) {
        if (bit == '0') {
            bit = '1';
        } else {
            bit = '0';
        }
    }
    return bin_inv;
}


std::string adaptedUDPLength(const std::string& ports, const std::string& checksum, const std::string& src_ip,
                             const std::string& dest_ip) {
    std::string correct_UDP_len;
    std::string zero_string = "0000";

//    Protocol = 17, because UDP, the zero-strings are mandatory padding
    std::string zeroes_protocol = zero_string + zero_string + std::bitset<8>(17).to_string();
    std::string src_ip_bin = ipToBin(src_ip);
    std::string dest_ip_bin = ipToBin(dest_ip);
    std::string udp_len = zero_string + zero_string + std::bitset<8>(8).to_string();

    debugPrint("checksum", checksum, false);

//    Now follows the process of reverse engineering the given checksum,
//    so we can edit the length-field in the UDP header to get ensure that the checksum is valid.
    std::string inv_check_sum = invHex(checksum);

    debugPrint("Inv check sum", inv_check_sum, false);

    std::string header_sum = hectetSum(
            binToHex(ports + zeroes_protocol + src_ip_bin + dest_ip_bin + udp_len));

    debugPrint("Hex hdr sum", header_sum, false);

//    Ensures that the length of the header sum is 4 (because it is in hexadecimal form).
//    By splitting them into two hectets and adding them together.
//    If the new header sum is still longer than 4, repeat.
    while (header_sum.size() > 4) {
        std::string padding;
        for (int i = 0; i < 8 - header_sum.size(); i++) {
            padding += "0";
        }
        header_sum = hectetSum(padding + header_sum);
    }

    header_sum = hexToBin(header_sum);
    inv_check_sum = hexToBin(inv_check_sum);
    if (binHectetIsLarger(inv_check_sum, header_sum)) {
        inv_check_sum = "1" + decrementBin(inv_check_sum, 1);
    }
    debugPrint("Hdr sum, bin", header_sum, false);
    debugPrint("corrected checksum", inv_check_sum, false);
    correct_UDP_len = binDiff(inv_check_sum, header_sum);
    debugPrint("udp len, no pad", correct_UDP_len, false);
    std::string padding;
    for (int i = 0; i < 16 - correct_UDP_len.size(); i++) {
        padding += "0";
    }
    return correct_UDP_len;
}

std::string binDiff(std::string bin1, const std::string& bin2) {
    /**
     * bin1 must be larger than bin2
     * Returns the result of bin1 - bin2
     */
    std::string diff = "0";
    while (bin1 != bin2) {
        bin1 = decrementBin(bin1, 1);
        diff = incrementHex(diff, 1);
    }
    return hexToBin(diff);
}

bool binHectetIsLarger(std::string hect1, std::string hect2) {
    /**
     * Returns whether the second binary hectet is larger than the first binary hectet.
     */
    for (int i = 0; i < hect1.size(); i++) {
        char bit_hect1 = hect1[i];
        char bit_hect2 = hect2[i];
        if (bit_hect1 == bit_hect2) {
            continue;
        } else if (bit_hect1 == '0' && bit_hect2 == '1') {
            return true;
        } else {
            return false;
        }
    }
//    Then equal, so not larger
    return false;
}


std::string createUDPHeader(int src_port, int dest_port, const std::string& checksum, const std::string& src_ip,
                            const std::string& dest_ip) {
    std::string udp_header;
//    Creation of the header fields
//    Source port
    std::string source_port = std::bitset<16>(src_port).to_string();
//    Destination port
    std::string destination_port = std::bitset<16>(dest_port).to_string();
    debugPrint("udp_size", udp_header.size(), false);
//    Length
    std::string data_len = std::bitset<16>(8).to_string();
    debugPrint("udp_size", udp_header.size(), false);
//    Checksum
    std::string udp_checksum = hexToBin(checksum);
    debugPrint("udp_size", udp_header.size(), false);

//    Partly creation of the UDP header
    udp_header += source_port;
    udp_header += destination_port;

    debugPrint("Before udp len", "", false);

//    Correct the length field, because we want a custom checksum
    data_len = adaptedUDPLength(udp_header, checksum, src_ip, dest_ip);

    debugPrint("After udp len", "", false);

//    Merge all the header fields
    udp_header += data_len;
    udp_header += udp_checksum;
    return udp_header;
}


uint16_t ipToShort(const std::string& ip) {
    std::string ip_as_bin = ipToBin(ip);
    return (uint16_t) binToInt(ip_as_bin);
}


uint32_t hexToInt(const std::string& hex) {
    std::string hex_as_bin = hexToBin(hex);
    return (uint32_t) binToInt(hex_as_bin);
}


std::string sendFinalmessage(int sock, char* buffer, std::string dest_ip, int port_nr) {
    char key_char_group_2 = 'H';

    std::string result = "";

    struct sockaddr_in destaddr;
    //  The msg in the buffer
    int buff_len = strlen(buffer);
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
                    debugPrint("recv_buff", recv_buff, false);
                    char first_char = recv_buff[0];
                    if (first_char == key_char_group_2) {
                        std::string checksum;
                        std::string chngd_src;
                        for (int i = CHECKSUM_START_IND; i < CHECKSUM_START_IND + 4; i++) {
                            checksum += recv_buff[i];
                        }
//                        Gets the checksum and the source ip for the next msg from this msg
                        int i = SRC_IP_START_IND;
                        while (true) {
                            char recv_char = recv_buff[i];
                            if (!(isdigit(recv_char) || (recv_char == '.'))) {
                                break;
                            }
                            chngd_src += recv_char;
                            i++;
                        }
                        debugPrint("checksum", checksum, false);
                        debugPrint("new_src_ip", chngd_src, false);

//                        Used to get the source port number
                        struct sockaddr_in sin;
                        socklen_t sin_len = sizeof(sin);
                        if (getsockname(sock, (struct sockaddr *)&sin, &sin_len) == -1) {
                            perror("getsockname");
                        }
                        int src_port = ntohs(sin.sin_port);

                        std::string ip_header;
                        std::string udp_header;

//                        TODO: Choose between either structs or custom
                        ip_header = createIPHeader(chngd_src, dest_ip);
                        udp_header = createUDPHeader(src_port, port_nr, checksum, chngd_src, dest_ip);

                        struct iphdr ip_hdr;
                        struct udphdr udp_hdr;

                        ip_hdr.version = 4;
                        ip_hdr.saddr = ipToShort(chngd_src);
                        udp_hdr.uh_sum = hexToInt(checksum);

//                        The msg that needs to be sent
                        std::string special_msg;
                        special_msg = ip_header + udp_header;
                        debugPrint("msg", special_msg, false);

//                        Creation of the buffer
                        char buff_special_msg[1400];
                        strcpy(buff_special_msg, special_msg.c_str());
                        return(sendFinalmessage(sock, buff_special_msg, dest_ip, port_nr));
                    }
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
//    that has a valid UDP checksum of <CHECKSUM>, and with the source address being <IP>!
//    (the last 6 bytes of this message contain this information in network order)z)/9
    char key_char2 = 'S';
    //    Send $group_47$, with evil bit
    char key_char3 = 'T';
    //    Find secret port, recv_buff[-5:-1]
    char key_char4 = 'M';
    std::vector<std::string> secret_ports;

    for (int i = 0; i < 4; i++) {
        int curr_port = open_ports[i];
        if (TEST_CUSTOM_HDR and curr_port != 4097) {
            continue;
        }
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
                            char buff_special_msg[1400];
                            strcpy(buff_special_msg, "$group_47$");
                            secret_ports.push_back(sendFinalmessage(sock, buff_special_msg, dest_ip, curr_port));
                        } else if (first_char == key_char3) {
//                            TODO: Send evil bit
                            const char* special_msg = "";
                            char buff_special_msg[1400];
                            strcpy(buff_special_msg, special_msg);
                            secret_ports.push_back(sendFinalmessage(sock, buff_special_msg, dest_ip, curr_port));
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