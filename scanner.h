struct sockaddr_in sock_opts(int sock, const std::string& dest_ip);

int socket_creation();

int char_pointer_to_int(char *argument);

void check_ip(const char *argument);

std::vector<int> find_open_ports(struct sockaddr_in destaddr, int from, int to, int sock,
                                 const void *buff, size_t buff_len);