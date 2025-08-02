#include "Connection.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")  // link winsock

Connection::Connection(const std::string& serverIP, int serverPort)
        : ip(serverIP), port(serverPort), sockfd(INVALID_SOCKET) {}

Connection::~Connection() {
    if (sockfd != INVALID_SOCKET) {
        closesocket(sockfd);
    }
    WSACleanup();
}

bool Connection::initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return false;
    }
    initialized = true;
    return true;
}

bool Connection::connectToServer() {
    if (!initialized && !initializeWinsock())
        return false;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == INVALID_SOCKET) {
        std::cerr << "Failed to create socket.\n";
        return false;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    int res = connect(sockfd, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    if (res == SOCKET_ERROR) {
        std::cerr << "Connection failed.\n";
        closesocket(sockfd);
        return false;
    }

    return true;
}

bool Connection::sendData(const std::vector<uint8_t>& data) {
    int totalSent = 0;
    while (totalSent < data.size()) {
        int sent = send(sockfd, reinterpret_cast<const char*>(data.data()) + totalSent,
                        data.size() - totalSent, 0);
        if (sent == SOCKET_ERROR) {
            std::cerr << "Send failed.\n";
            return false;
        }
        totalSent += sent;
    }
    return true;
}

bool Connection::receiveData(std::vector<uint8_t>& buffer, size_t sizeToRead) {
    buffer.resize(sizeToRead);
    size_t totalReceived = 0;
    while (totalReceived < sizeToRead) {
        int received = recv(sockfd, reinterpret_cast<char*>(buffer.data()) + totalReceived,
                            sizeToRead - totalReceived, 0);
        if (received <= 0) {
            std::cerr << "Receive failed or connection closed.\n";
            return false;
        }
        totalReceived += received;
    }
    return true;
}
