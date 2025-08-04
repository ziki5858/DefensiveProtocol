#pragma once
#include <winsock2.h>
#include <string>
#include <vector>
#include <cstdint>

class Connection {
public:
    Connection(const std::string& serverIP, int serverPort);
    ~Connection();

    // Establishes connection (init Winsock + connect socket)
    bool connectToServer();

    // Sends a complete message (header+payload) and receives full response
    std::vector<uint8_t> sendAndReceive(const std::vector<uint8_t>& data);

private:
    bool initializeWinsock();
    bool sendData(const std::vector<uint8_t>& data);
    bool receiveData(std::vector<uint8_t>& buffer, size_t sizeToRead);

    std::string ip;
    int port;
    SOCKET  sockfd;
    bool initialized = false;
};

