output: client.o server.o
	./client

client.o: server.h
	g++ client.cpp -o client

server.o: server.h
	./main 130.208.242.120 4042 4097 4098 4099
	
server.h:
	g++ main.cpp -o main