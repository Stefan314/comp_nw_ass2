# Computer Networks Assignment 2
    Isabel Stein        Stefan Deelen
    isabels21@ru.is     stefand21@ru.is

## How to run the code
Go to the directory where the Makefile, file is located in the command prompt. 
Type 'make' to compile the files. 
Type './scanner <ip-addr> <low port> <high port>' to scan for open ports on the given ip-address between the two ports.
If the high port is set lower than the low port, it will be set to low port + 100.
These parameters are however optional, the default ip is: '130.208.242.120'. 
The default low port is 4000. The default high port is 4100.