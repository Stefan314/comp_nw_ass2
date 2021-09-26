struct sockaddr_in sock_opts(int sock, const std::string& dest_ip, int timeout_ms);

int socket_creation();

int char_pointer_to_int(std::basic_string<char> argument);

void check_ip(const char *argument);

std::vector<int> find_open_ports(struct sockaddr_in destaddr, int from, int to, int sock,
                                 const void *buff, size_t buff_len, int no_of_retries);