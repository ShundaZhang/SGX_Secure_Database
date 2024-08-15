# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -Wall -I/usr/include/cpprest
LDFLAGS = -lcpprest -lssl -lcrypto -lboost_system -lboost_thread -pthread

# Directories
CERT_DIR = .
SRC_DIR = .
OBJ_DIR = .
BIN_DIR = .

# Files
SRC = $(SRC_DIR)/server.cpp
OBJ = $(OBJ_DIR)/server.o
BIN = $(BIN_DIR)/server

# Certificate files
KEY_FILE = $(CERT_DIR)/server.key
CRT_FILE = $(CERT_DIR)/server.crt
PEM_FILE = $(CERT_DIR)/server.pem

# Targets
all: $(BIN)

$(BIN): $(OBJ) $(PEM_FILE)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

$(OBJ): $(SRC)
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(PEM_FILE): $(KEY_FILE) $(CRT_FILE)
	cat $(CRT_FILE) $(KEY_FILE) > $(PEM_FILE)

$(KEY_FILE):
	@mkdir -p $(CERT_DIR)
	openssl genpkey -algorithm RSA -out $(KEY_FILE)

$(CRT_FILE): $(KEY_FILE)
	openssl req -new -x509 -key $(KEY_FILE) -out $(CRT_FILE) -days 365 -subj "/C=US/ST=California/L=San Francisco/O=YourCompany/OU=YourUnit/CN=10.239.166.47"

clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/server $(CERT_DIR)/server.key $(CERT_DIR)/server.crt $(CERT_DIR)/server.pem ./*.txt

.PHONY: all clean

