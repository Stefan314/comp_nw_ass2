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
#include <algorithm>
using namespace std;

int noOfRetries = 20;
// In milliseconds
int timeout = 400;
bool hardCodeHiddenPorts = true;
// Used for testing TODO: Set all to false in final version.
bool debug = false;
bool hardCodedPorts = true;
bool testCustomHeader = false;
//    The payload if the program needs to send the group number.
const char *groupNumber = "$group_47$";

void messageHandler(const vector<int>& open_ports, int sock, char *buffer, const string& dest_ip);

bool binLarger(string bin1, string bin2);

string binDiff(string bin1, const string& bin2);

uint16_t removeShortOverflow(uint32_t header_sum);

uint16_t adaptedUDPSrcPort(udphdr *udp_hdr, const string& src_ip, const string& dest_ip);

string invBin(string bin);

uint16_t ipToShort(const string& ip);

uint32_t hexToInt(const string& hex);

void debugPrint(const string &arg_name, const string &arg, bool debug_override);

void debugPrint(const string &arg_name, unsigned long arg, bool debug_override);

string hexToBin(const string& hexadec);

string decrementBin(string bin, int decrement);

string incrementHex(string hex, int increment);

string binToHex(const string& bin);

string decrementHex(string hex, int decrement);

string hexAddition(string hex1, string hex2);

string hextetSum(string hex);

string invHex(const string& hext);

string ipToBin(const string& ip);

uint16_t ipChecksum(struct iphdr ip_hdr);

string createCorrectId(const string& desired_checksum, const string& calc_checksum);

char binToChar(const string& bin);

string binToChars(const string& bin);

vector<string> split(const string& str_to_split, const string& delim);

vector<int> stringVecToIntVec(const vector<string>& str_vec);

string sendAndReceive(int sock, char *buffer, const string &dest_ip, const vector<int>& dest_ports);

string sendAndReceive(int sock, char *buffer, const string &dest_ip, int dest_port);

string checksumPortHandler(int sock, const string &dest_ip, const int &port);

string evilBitHandler(int sock, const string &destIP, const int &port);

string checksumPortHandler2(int sock, string response, const string& dest_ip, int port);

string checksumPortHandler3(int sock, const string &dest_ip, int port, const string& new_UDP_checksum, const string& new_src_ip);

string oraclePortHandler(int sock, vector<string> secret_ports, const string& dest_ip, int port);

string oraclePortHandler2(int sock, const string &dest_ip, string response);

int main(int argc, char *argv[]) {
//    Default parameters which might be changed depending on how many arguments are given.
//    Default ip-address
    string dest_ip = "130.208.242.120";
//    The secret ports
    vector<int> open_ports;

//    The UDP socket
    int sock = socket_creation();
    struct sockaddr_in destaddr = sock_opts(sock, dest_ip, timeout);

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
        if (hardCodedPorts) {
            open_ports.push_back(4042);
            open_ports.push_back(4097);
            open_ports.push_back(4098);
            open_ports.push_back(4099);
        } else {
            open_ports = find_open_ports(destaddr, from, to, sock, buffer, buff_len, noOfRetries);
        }
    }

    messageHandler(open_ports, sock, buffer, dest_ip);
}

void debugPrint(const string &arg_name, const string &arg, bool debug_override) {
    if (debug || debug_override) {
        cout << arg_name + "=" << arg << "\n";
    }
}

void debugPrint(const string &arg_name, unsigned long arg, bool debug_override) {
    debugPrint(arg_name, to_string(arg), debug_override);
}

/**
 * Converts a hexadecimal to a binary number.
 * Partially inspired by user https://stackoverflow.com/users/1951468/silex on thread
 * https://stackoverflow.com/questions/18310952/convert-strings-between-hexadec-format-and-binary-format
 * @param hexadec The string representation of a hexadecimal number.
 * @return The hexadecimal number, converted to binary.
 */
string hexToBin(const string& hexadec) {
    string bin;
    for (auto&& hexa : hexadec) {
        stringstream stream;
        stream << hex << hexa;
        unsigned result;
        stream >> result;
//        4, because hexadecimal is base 16, which is 2^4, so 4 bits
        bitset<4> b(result);
        bin += b.to_string();
    }
    return bin;
}

string decrementBin(string bin, int decrement) {
    for (int i = 0; i < decrement; i++) {
        char last_bit = bin.at(bin.size() - 1);
        string replacement = "0";
        switch (last_bit) {
            case '0':
                replacement = "1";
                if (bin.size() > 1) {
                    bin = decrementBin(bin.substr(0, bin.size() - 1), 1).append(replacement);
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

string decrementHex(string hex, int decrement) {
    for (int i = 0; i < decrement; i++) {
        char last_hex = hex.at(hex.size() - 1);
        string replacement = "0";
        switch (last_hex) {
            case '0':
                replacement = "f";
                if (hex.size() > 1) {
                    hex = decrementHex(hex.substr(0, strlen(hex.c_str()) - 1), 1).
                            append(replacement);
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

string incrementHex(string hex, int increment) {
    for (int i = 0; i < increment; i++) {
        char last_hex = hex.at(hex.size() - 1);
        string replacement = "0";
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
                    hex.insert(0, "0");
                }
                hex = incrementHex(hex.substr(0, strlen(hex.c_str()) - 1), 1).append(replacement);
                break;
            default:
                break;
        }
        hex.replace(strlen(hex.c_str()) - 1, 1, replacement);
    }
    return hex;
}

string hexAddition(string hex1, string hex2) {
    bool hex2_is_zeroes = all_of(hex2.begin(), hex2.end(), '0');
    while (!hex2_is_zeroes) {
        hex1 = incrementHex(hex1, 1);
        hex2 = decrementHex(hex2, 1);
        hex2_is_zeroes = all_of(hex2.begin(), hex2.end(), '0');
    }
    return hex1;
}

string hextetSum(string hex) {
    string hextet_sum = "0000";

    while (!hex.empty()) {
        debugPrint("hex", hex, false);

        string hextet = hex.substr(0, 4);
        debugPrint("hextet", hextet, false);

        hex = hex.substr(4, hex.size() - 4);
        hextet_sum = hexAddition(hextet_sum, hextet);
        debugPrint("hextet_sum", hextet_sum, false);
    }
    return hextet_sum;
}

string invHex(const string& hext) {
    string inv_hext;

    for (auto &&hex : hext) {
        switch(hex) {
            case '0':
                inv_hext += "f";
                break;
            case '1':
                inv_hext += "e";
                break;
            case '2':
                inv_hext += "d";
                break;
            case '3':
                inv_hext += "c";
                break;
            case '4':
                inv_hext += "b";
                break;
            case '5':
                inv_hext += "a";
                break;
            case '6':
                inv_hext += "9";
                break;
            case '7':
                inv_hext += "8";
                break;
            case '8':
                inv_hext += "7";
                break;
            case '9':
                inv_hext += "6";
                break;
            case 'A':
            case 'a':
                inv_hext += "5";
                break;
            case 'B':
            case 'b':
                inv_hext += "4";
                break;
            case 'C':
            case 'c':
                inv_hext += "3";
                break;
            case 'D':
            case 'd':
                inv_hext += "2";
                break;
            case 'E':
            case 'e':
                inv_hext += "1";
                break;
            case 'F':
            case 'f':
                inv_hext += "0";
                break;
            default:
                break;
        }
    }
    debugPrint("inv_hext", inv_hext, false);
    return inv_hext;
}

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

vector<int> stringVecToIntVec(const vector<string>& str_vec) {
    vector<int> result;

    result.reserve(str_vec.size());
    for (const string& str : str_vec) {
        result.push_back(char_pointer_to_int(str));
    }
    return result;
}

uint16_t ipChecksum(struct iphdr ip_hdr) {
    string vers = bitset<4>(ip_hdr.version).to_string();
    string ihl = bitset<4>(ip_hdr.ihl).to_string();
    string tos = bitset<8>(ip_hdr.tos).to_string();
    uint32_t vers_ihl_dscp_ecn_hext = stoi(vers + ihl + tos, nullptr, 2);

    uint32_t tot_len = ip_hdr.tot_len;
    uint32_t id = ip_hdr.id;
    uint32_t flag_frag_hext = ip_hdr.frag_off;

    string ttl = bitset<16>(ip_hdr.ttl).to_string();
    string prot = bitset<16>(ip_hdr.protocol).to_string();
    uint32_t ttl_prot_hext = stoi(ttl + prot, nullptr, 2);

    string src_ip = bitset<32>(ip_hdr.saddr).to_string();
    uint32_t src_ip_hext1 = stoi(src_ip.substr(0, 16), nullptr, 2);
    uint32_t src_ip_hext2 = stoi(src_ip.substr(16, 16), nullptr, 2);

    string dest_ip = bitset<32>(ip_hdr.daddr).to_string();
    uint32_t dest_ip_hext1 = stoi(dest_ip.substr(0, 16), nullptr, 2);
    uint32_t dest_ip_hext2 = stoi(dest_ip.substr(16, 16), nullptr, 2);

    uint32_t hext_sum = vers_ihl_dscp_ecn_hext + tot_len + id + flag_frag_hext + ttl_prot_hext +
                        src_ip_hext1 + src_ip_hext2 + dest_ip_hext1 + dest_ip_hext2;
    debugPrint("h_sum", hext_sum, false);

    hext_sum = removeShortOverflow(hext_sum);
    debugPrint("h_sum", hext_sum, false);

    uint16_t inv_hext = stoi(invBin(bitset<16>(hext_sum).to_string()), nullptr, 2);

    return inv_hext;
}

string createCorrectId(const string& desired_checksum, const string& calc_checksum) {
    string id = "0000";
    string cal_checksum_hex = binToHex(calc_checksum);
    debugPrint("des_sc", desired_checksum, false);

    while (desired_checksum != cal_checksum_hex) {
        debugPrint("cal_cs", cal_checksum_hex, false);
        id = incrementHex(id, 1);
        cal_checksum_hex = incrementHex(cal_checksum_hex, 1);
    }
    return hexToBin(id);
}

char binToChar(const string& bin) {
    return (char) stoi(bin, nullptr, 2);
}

string binToChars(const string& bin) {
    string chars;
    int step_size = 8;
    for (int i = 0; i < bin.size(); i += step_size) {
        string char_as_bin = bin.substr(i, step_size);
        chars += binToChar(char_as_bin);
    }
    return chars;
}

struct iphdr createIPHeader(const string& src_ip, const string& dest_ip, unsigned int flag) {
    struct iphdr ip_hdr;
//    Creation of all the header fields.
//    Version = 4, because ipv4
    unsigned int version = htons(4);
//    IHL = 5, because no options
    unsigned int ihl = htons(5);
//    DSCP = 0, because not necessary here
//    ECN = 0, because not necessary here
    uint8_t dscp_ecn = htons(0);
//    Total length = 28, because IP + UDP header = 20 bytes + 8 bytes respectively
    uint16_t len_total = htons(28);
//    Identification = 0, because not necessary here
    uint16_t id = htons(0);
//    Flags = 0, because doesn't matter here
//    Fragment offset = 0, data is at regular position
    string flag_str = bitset<3>(flag).to_string();
    string frag_off = bitset<13>(0).to_string();
    uint16_t flag_frag = htons(stoi(flag_str + frag_off,nullptr, 2));
//    Time To Live = 250, so we can have a decent TTL
    uint8_t ttl = htons(250);
//    Protocol = 17, because UDP
    uint8_t prot = htons(17);
//    Header checksum = 0, so it won't be checked B)
    uint16_t ip_checksum = htons(0);
//    For th ip-addresses, stoll is used, because they can't fit in a positive integer.
//    Since that uses 31 bits for the default 32 bit env.
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
    ip_hdr.protocol = prot;
    ip_hdr.check = ip_checksum;
    ip_hdr.saddr = src_ip_int;
    ip_hdr.daddr = dest_ip_int;
    return ip_hdr;
}

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

uint16_t adaptedUDPSrcPort(udphdr *udp_hdr, const string& src_ip, const string& dest_ip) {
    uint16_t correct_UDP_src_port;
    string src_ip_bin = ipToBin(src_ip);
    debugPrint("sip bin", src_ip_bin, false);
    uint32_t src_ip_1 = stoi(src_ip_bin.substr(0, 16), nullptr, 2);
    uint32_t src_ip_2 = stoi(src_ip_bin.substr(16, 16), nullptr, 2);
    string dest_ip_bin = ipToBin(src_ip);
    debugPrint("dip bin", dest_ip_bin, false);
    uint32_t dest_ip_1 = stoi(dest_ip_bin.substr(0, 16), nullptr, 2);
    uint32_t dest_ip_2 = stoi(dest_ip_bin.substr(16, 16), nullptr, 2);
//    Protocol = 17, because UDP, the zero-strings are mandatory padding
    uint8_t protocol = 17;
//    Just a copy of the length in the udp header
    uint32_t udp_len = udp_hdr->len;

//    Now follows the process of reverse engineering the given checksum,
//    so we can edit the length-field in the UDP header to get ensure that the checksum is valid.
    debugPrint("check", udp_hdr->check, false);
    string check_bin = bitset<16>(udp_hdr->check).to_string();
    debugPrint("check bin", check_bin, false);
    string inv_check_bin = invBin(check_bin);
    debugPrint("i check bin", inv_check_bin, false);
    uint32_t inv_check_sum = stoi(inv_check_bin, nullptr, 2);

    debugPrint("Inv check sum", inv_check_sum, false);

    uint32_t header_sum = src_ip_1 + src_ip_2 + dest_ip_1 + dest_ip_2 + protocol + udp_len + udp_hdr->len +
            udp_hdr->dest;

    debugPrint("Hex hdr sum", header_sum, false);

    header_sum = removeShortOverflow(header_sum);

    int max_size = 16;
    int max_short = (int) pow(2, max_size) - 1;
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
 * @param header_sum An integer that might not be overflowing when converted into a hextet.
 * @return A hextet in integer format.
 */
uint16_t removeShortOverflow(uint32_t header_sum) {
//    By splitting it into two parts.
//    Such that the right part is a hextet, the remaining part is padded to also form a hextet.each 16, long. The left part is padded.
//    If the new header sum is still longer than 16, repeat.
    int max_size = 4;
    string hs_hex = binToHex(bitset<32>(header_sum).to_string());
    debugPrint("hs hex", hs_hex, false);

//    Loop until no more overflow exists.
    while (hs_hex.size() > max_size) {
/* Splits the header sum into two parts, such that the right part is a hextet.
 * The remaining part on the left is padded, such that it also forms a hextet. */
        string padding;
        for (int i = 0; i < 2 * max_size - hs_hex.size(); i++) {
            padding += "0";
        }
        hs_hex = hextetSum(padding.append(hs_hex));
    }
    debugPrint("Hs hex, no overflow", hs_hex, false);
    header_sum = stoi(hs_hex, nullptr, 16);
    return header_sum;
}

/**
 * Finds the difference between two binary strings.
 * @param bin1 must be larger than bin2.
 * @param bin2 must be smaller or equal to bin1.
 * @return The result of bin1 - bin2.
 */
string binDiff(string bin1, const string& bin2) {
    string diff = "0";
    while (bin1 != bin2) {
        bin1 = decrementBin(bin1, 1);
        diff = incrementHex(diff, 1);
    }
    return hexToBin(diff);
}

/**
 * Finds which binary string is larger.
 * @return Whether the second binary string is larger than the first binary string.
 */
bool binLarger(string bin1, string bin2) {
    for (int i = 0; i < bin1.size(); i++) {
        char bit_hext1 = bin1[i];
        char bit_hext2 = bin2[i];
        if (bit_hext1 == bit_hext2) {
            continue;
        } else if (bit_hext1 == '0' && bit_hext2 == '1') {
            return true;
        } else {
            return false;
        }
    }
//    Then equal, so not larger
    return false;
}

struct udphdr createUDPHeader(int dest_port, const string& checksum, const string& src_ip,
                            const string& dest_ip) {
    struct udphdr udp_hdr;
//    Creation of the header fields
//    Source port = 0, will be changed later
    uint16_t src = htons(0);
//    Destination port
    uint16_t dest = htons(dest_port);
//    Length = 8, because UDP's header is 8
    uint16_t len = htons(8);
//    Checksum
    debugPrint("check, pre-stoi", checksum, false);
    uint16_t check = htons(stoi(checksum, nullptr, 16));
    debugPrint("check, post-stroi", check, false);

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

void messageHandler(const vector<int>& open_ports, int sock, char *buffer, const string& dest_ip) {
/* This is the port we need to send the comma seperated list of secret ports to.
 * Set to -1, to detect that this port wasn't picked up. */
    int oracle_port = -1;
    vector<string> secret_ports;
// This is used for when this program cannot solve the puzzle yet.
    if (hardCodeHiddenPorts) {
        secret_ports.emplace_back("4014");
    }

/* These are some key-characters for determining what message was sent to find what to respond.
 * These characters, correspond to the first character in the given message. */

/* This character corresponds to the port that wants to receive a comma separated list, the oracle port.
 * If this is done correctly, another comma separated list is returned.
 * Which contain the ports that need to be knocked on in that order to get the secret message.
 * Knocking is just sending an arbitrary message, such as "Hey port!". */
    char key_char1 = 'I';

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
    char key_char2 = 'S';

/* This character corresponds to the port that,
 * similarly to the message that the corresponding port of the previously mentioned character wanted to receive,
 * wants to receive the message of the form "$group_#$", where # is the group number, in this case that is 47.
 * This port will be called the 'evil port'.
 * However, the evil-bit needs to be set to 1 in the actual ip-header (so not sending the IPV4-header as a payload).
 * The evil-bit is one of the flags (the first) in the IPV4-header that is usually reserved to be 0.
 * To accomplish this, one must use a raw socket, so the headers can be changed. */
    char key_char3 = 'T';

/* This character corresponds to the port that we can do string parsing on to find one of the hidden ports,
 * that need to be in the comma separated list that the oracle wants to receive.
 * This port will be called the 'parsing port'.
 * This hidden port is always 4 digits long and has a period after it, which is the end of the message.
 * I.e., the hidden port can be found in msg.substring(len(msg) - 5, len(msg) - 1),
 * where the second parameter is the ending index, which is exclusive. */
    char key_char4 = 'M';

    for (auto&& open_port : open_ports) {
//        Used for testing msg where we put custom headers in the payload. Should not be run during the final version.
        if (testCustomHeader and open_port != 4097) {
            continue;
        }
        string response = sendAndReceive(sock, buffer, dest_ip, open_port);
        char response_start = response[0];
        if (response_start == key_char1) {
//            This is the oracle port.
            oracle_port = open_port;
        }
        else if (response_start == key_char2) {
//            This is the checksum port.
            response = checksumPortHandler(sock, dest_ip, open_port);
        }
        else if (response_start == key_char3) {
//            This is the evil port.
            response = evilBitHandler(sock, dest_ip, open_port);
        }
        else if (response_start == key_char4) {
//            This is the parsing port.
            string secret_port = response.substr(response.size() - 5, 4);
            secret_ports.push_back(secret_port);
        }
    }
    string response = oraclePortHandler(sock, secret_ports, dest_ip, oracle_port);
}

string oraclePortHandler(int sock, vector<string> secret_ports, const string& dest_ip, int port) {
//    Sending the correct message to the oracle port.
    string secret_ports_csl;
    for (int i = 0; i < secret_ports.size(); i++) {
        secret_ports_csl += secret_ports[i];
        if (i < secret_ports.size() - 1) {
            secret_ports_csl += ", ";
        }
    }
    char buff_special_msg[1400];
    strcpy(buff_special_msg, secret_ports_csl.c_str());
    string response = sendAndReceive(sock, buff_special_msg, dest_ip, port);
    return oraclePortHandler2(sock, dest_ip, response);
}

string oraclePortHandler2(int sock, const string &dest_ip, string response) {
/* This character corresponds successfully sending the comma seperated list, correctly formatted, to the oracle port.
 * To summarise what has been stated previously for what the next step is.
 * The port will send the program a different comma seperated list.
 * The program needs to knock on these ports in the correct order to get the secret message. */
    char key_char1_2 = '4';

    if (response[0] == key_char1_2) {
        vector<int> port_knox = stringVecToIntVec(split(response, ","));
        char buff[1400];
        strcpy(buff, "Hey Port");
//        TODO: Fix, does not detect response correctly.
        return sendAndReceive(sock, buff, dest_ip, port_knox);
    }
    return "";
}

string checksumPortHandler(int sock, const string &dest_ip, const int &port) {
    string parsed_string;
    char buff_group_msg[1400];
    strcpy(buff_group_msg, groupNumber);
    string response = sendAndReceive(sock, buff_group_msg, dest_ip, port);

    if (!hardCodeHiddenPorts) {
        response = checksumPortHandler2(sock, response, dest_ip, port);
//        TODO: Change this to do something with the response.
//        secret_ports.push_back(response);
    }
    return parsed_string;
}

string checksumPortHandler2(int sock, string response, const string& dest_ip, int port) {
/* This character corresponds to successfully sending the group number, correctly formatted, to the checksum port.
 * To summarise what has been stated previously for what the next step is.
 * The program needs to send a changed IPV4- and UDP-header as a payload.
 * The previous response contains the information as to change which header fields and how. */
    char key_char2_2 = 'H';

    string new_UDP_checksum;
    string new_src_ip;
//    The previously mentioned values always start at the same index in the message.
    int checksum_start_idx = 146;
    int src_ip_start_idx = 186;

//    Gets the new UDP checksum and the new source ip for the next msg from this msg
//    Since the checksum is in hexadecimal form, it is always of length 4.
    int checksum_size = 4;
    for (int i = checksum_start_idx; i < checksum_start_idx + 4; i++) {
        new_UDP_checksum += response[i];
    }
    int i = src_ip_start_idx;
    char curr_char = response[i];
//    The given IP-address consists of digits separated by periods.
//    The distance between the periods can differ.
    while (isdigit(curr_char) || curr_char == '.') {
        new_src_ip += curr_char;
        i++;
        curr_char = response[i];
    }
    debugPrint("new_UDP_checksum", new_UDP_checksum, false);
    debugPrint("new_src_ip", new_src_ip, false);

    return checksumPortHandler3(sock, dest_ip, port, new_UDP_checksum, new_src_ip);
}

string checksumPortHandler3(int sock, const string &dest_ip, int port, const string& new_UDP_checksum,
                            const string& new_src_ip) {
//    Creation of the buffer
    char buff_special_msg[1400];

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
    uint16_t flag_frag = htons(stoi(flag_str + frag_off,nullptr, 2));

//    Time To Live = 250, so we can have a decent TTL
    uint8_t ttl = htons(250);
//    Protocol = 17, because we're using a UDP-header
    uint8_t prot = htons(17);
//    Header checksum = 0, so it won't be checked
    uint16_t ip_checksum = htons(0);

/* For the ip-addresses, stoll is used, instead of stoi, because they can't fit in a positive integer.
 * Since that uses 31 bits for the default 32 bit environment. Since the first bit denotes the sign of the integer. */
//    Source IP address
    debugPrint("new_src_ip", new_src_ip, false);
    string src_ip_str = ipToBin(new_src_ip);
    debugPrint("s_ip_str", src_ip_str, false);
    uint32_t src_ip_int = htons(stoll(src_ip_str, nullptr, 2));
    debugPrint("src_ip_int", src_ip_int, false);
//    Destination IP address
    debugPrint("dest_ip", dest_ip, false);
    string dest_ip_str = ipToBin(dest_ip);
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
    ip_hdr->protocol = prot;
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
    debugPrint("check, pre-stoi", new_UDP_checksum, false);
    uint16_t check = htons(stoi(new_UDP_checksum, nullptr, 16));
    debugPrint("check, post-stroi", check, false);

//    Partial creation of the UDP-header
    udp_hdr->dest = dest;
    udp_hdr->len = len;
    udp_hdr->check = check;

//    Correct the source port field, because we want a custom checksum
    src = htons(adaptedUDPSrcPort(udp_hdr, new_src_ip, dest_ip));

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
    debugPrint("iphdr prot", ip_hdr->protocol, false);
    debugPrint("iphdr check", ip_hdr->check, false);
    debugPrint("iphdr sad", ip_hdr->saddr, false);
    debugPrint("iphdr dad", ip_hdr->daddr, false);

//    Printing udp header info
    debugPrint("udphdr src", udp_hdr->source, false);
    debugPrint("udphdr dest", udp_hdr->dest, false);
    debugPrint("udphdr len", udp_hdr->len, false);
    debugPrint("udphdr check", udp_hdr->check, false);

//    TODO: Remove this commented out code in final version.
//    strcpy(buff_special_msg, "$group_47$");
//    memcpy(buff_special_msg, &ip_hdr, sizeof(*ip_hdr));
//    Make the udp header appear after the ip header in the buffer
//    memcpy(buff_special_msg + sizeof(*ip_hdr), &udp_hdr, sizeof(*udp_hdr));
    debugPrint("buffer", buff_special_msg, false);

    return sendAndReceive(sock, buff_special_msg, dest_ip, port);
}

string evilBitHandler(int sock, const string &destIP, const int &port) {
//    TODO: Send group number with evil bit set to 1.
    const char* special_msg = "";
    char buff_special_msg[1400];
    strcpy(buff_special_msg, special_msg);
    string response = sendAndReceive(sock, buff_special_msg, destIP, port);
    if (!hardCodeHiddenPorts) {
//      TODO: Change this to do something with the response.
//      secret_ports.push_back(response);
    }
    return "";
}

/**
 * Tries to send a message and receive the response to the ports in the same order they are given in
 * @param sock The socket it needs to send the messages to
 * @param buffer The message that needs to be sent.
 * @param dest_ip The ip-address that needs to receive the message.
 * @param dest_ports The ports that the message need to be sent to.
 * @return The received message if there is any. If there is no response, then it will return the empty string.
 */
string sendAndReceive(int sock, char *buffer, const string &dest_ip, const vector<int>& dest_ports) {
/* This character represents the first character of the message saying that there was a checksum error server-side.
 * The program will retry that port. */
    char error_char = 'R';
    struct sockaddr_in dest_addres{};
    dest_addres.sin_family = AF_INET;
    inet_aton(dest_ip.c_str(), &dest_addres.sin_addr);
    char recv_buff[1400];
/* Amount of times you want to try and send the message and try to receive one as well.
 * If it didn't receive anything, we conclude that the port is not open. */
    for (int i = 0; i < noOfRetries; i++)  {
//        Sends the ports in the given order
        for (auto&& dest_port : dest_ports) {
            dest_addres.sin_port = htons(dest_port);
            try {
                if (sendto(sock, buffer, strlen(buffer), 0, (const struct sockaddr *) &dest_addres,
                        sizeof(dest_addres)) < 0) {
//                    Could not send the msg
                    perror("Could not send");
                }
            }
            catch (const overflow_error &e) {
                throw overflow_error("could not send");
            }
        }
//        Detects whether anything is received.
        memset(recv_buff, 0, sizeof(recv_buff));
        recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct sockaddr *) &dest_addres,
                 reinterpret_cast<socklen_t *>(sizeof(dest_addres)));

//        TODO: Check ip here instead of error, and fix in general
//        Error number 14 means bad address, but it receives the correct info. So it works.
        if (errno == 14) {
            debugPrint("recv_buff", recv_buff, false);
            char first_char = recv_buff[0];
            if (first_char == error_char) {
//                There is a random checksum error server-side. Try sending and receiving again.
                continue;
            }
            return recv_buff;
        }
    }
    return "";
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
    return sendAndReceive(sock, buffer, dest_ip, dest_ports);
}
