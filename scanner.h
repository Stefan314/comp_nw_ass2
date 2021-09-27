#include <vector>
#include <string>
using namespace std;

extern int noOfRetries;
// In milliseconds
extern int timeout;
extern bool debugOverride;

struct sockaddr_in sockOpts(int sock, const string &destIP);

int socketCreation();

bool checkIp(const string& argument);

vector<int> findOpenPorts(const string &destIP, int from, int to, int sock, int max_ports);

vector<string> sendAndReceive(int sock, char *buffer, const string &destIP, const vector<int>& dest_ports);

string sendAndReceive(int sock, char *buffer, const string &dest_ip, int dest_port);

void debugPrint(const string &argName, const string &arg, bool debug);

void debugPrint(const string &argName, unsigned long arg, bool debug);

void runScanner(int argc, char *argv[]);

vector<string> split(const string& strToSplit, const string& delim);

vector<int> stringVecToIntVec(const vector<string>& strVec);