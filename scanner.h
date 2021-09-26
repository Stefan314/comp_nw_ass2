#include <vector>
#include <string>
using namespace std;

extern int noOfRetries;
// In milliseconds
extern int timeout;
extern bool debug;

struct sockaddr_in sockOpts(int sock, const string &dest_ip);

int socketCreation();

bool checkIp(const string& argument);

vector<int> findOpenPorts(const string &dest_ip, int from, int to, int sock, int max_ports);

string sendAndReceive(int sock, char *buffer, const string &dest_ip, const vector<int>& dest_ports);

string sendAndReceive(int sock, char *buffer, const string &dest_ip, int dest_port);

void debugPrint(const string &arg_name, const string &arg, bool debug_override);

void debugPrint(const string &arg_name, unsigned long arg, bool debug_override);

void runScanner(int argc, char *argv[]);

vector<string> split(const string& str_to_split, const string& delim);

vector<int> stringVecToIntVec(const vector<string>& str_vec);