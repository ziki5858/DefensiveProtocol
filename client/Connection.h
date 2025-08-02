#pragma once

#include <string>
#include <vector>
#include <cstdint>

class Connection {
public:
    Connection(const std::string& serverIP, int serverPort);
    ~Connection();

    bool connectToServer();
    bool sendData(const std::vector<uint8_t>& data);
    bool receiveData(std::vector<uint8_t>& buffer, size_t sizeToRead);

private:
    std::string ip;
    int port;
    int sockfd; // socket file descriptor

    bool initialized = false;
    bool initializeWinsock(); // for Windows (optional)
    void cleanup();           // for Windows (optional)
};
