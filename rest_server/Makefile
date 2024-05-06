CC = g++
CFLAGS = -std=c++11
LIBS = -lboost_system -lcpprest -lssl -lcrypto -pthread

server: server.cpp
	$(CC) $(CFLAGS) -o server server.cpp $(LIBS)

.PHONY: clean
clean:
	rm -f server

