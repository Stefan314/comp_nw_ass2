# Computer Networks Assignment 2
    Isabel Stein        Stefan Deelen
    isabels21@ru.is     stefand21@ru.is

## How to run the code
Go to the directory where the Makefile file is located in the command prompt. 
Type 'make' to compile the files. 

### Scanner

Type './scanner <ip-addr> <low port> <high port>' 
to scan for open ports on the given ip-address in the range of <low port> to <high port> the two ports.  

For user-friendliness, the user does not need to enter all these arguments.  
If the high port is left out, it will be set to <low port> + 100.  
If both ports are left out, they will be set to 4000 and 4100 respectively.  
If the IP-address is not given either, then it will be set to "130.208.242.120"  
The user will be notified when it has not given sufficient arguments on the command line.

The program will stop scanning for ports when it has found 4 open ports, since we only want to know the 4 open ports. 
This is done for efficiency.

The scanner will try to connect to a port 10 times for 400 ms (timeout). 
If it could not connect, the program assumes that the port is not open. 

### Puzzlesolver
Type './puzzlesolver <ip-addr> <port 1> <port 2> <port 3> <port 4>' 
to solve the puzzle on the given IP-address for the given open ports.

For user-friendliness, the user does not need to enter all these arguments.  
If any of the 4 ports are not given, it will perform the scan, similar to the scanner file, 
where only the IP-address is given.  
If the IP-address is not given either, then it will be set to "130.208.242.120"  
The user will be notified when it has not given sufficient arguments on the command line.

When the puzzle is solved, the user should be sent a message that says "You have knocked. You may enter"