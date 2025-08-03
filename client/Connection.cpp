#include "Connection.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

Connection::Connection(const std::string& serverIP, int serverPort)
        : ip(serverIP), port(serverPort), sockfd(INVALID_SOCKET) {}

Connection::~Connection() {
    if (sockfd != INVALID_SOCKET) {
        closesocket(sockfd);
    }
    if (initialized) {
        WSACleanup();
    }
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
        std::cerr << "Failed to create socket." << std::endl;
        return false;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    int res = connect(sockfd, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    if (res == SOCKET_ERROR) {
        std::cerr << "Connection failed." << std::endl;
        closesocket(sockfd);
        sockfd = INVALID_SOCKET;
        return false;
    }
    return true;
}

bool Connection::sendData(const std::vector<uint8_t>& data) {
    int totalSent = 0;
    while (totalSent < static_cast<int>(data.size())) {
        int sent = send(sockfd, reinterpret_cast<const char*>(data.data()) + totalSent,
                        data.size() - totalSent, 0);
        if (sent == SOCKET_ERROR) {
            std::cerr << "Send failed." << std::endl;
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
            std::cerr << "Receive failed or connection closed." << std::endl;
            return false;
        }
        totalReceived += received;
    }
    return true;
}

std::vector<uint8_t> Connection::sendAndReceive(const std::vector<uint8_t>& data) {
    if (sockfd == INVALID_SOCKET && !connectToServer()) {
        throw std::runtime_error("Unable to connect to server");
    }

    if (!sendData(data)) {
        throw std::runtime_error("Failed to send data");
    }

    // First receive header (23 bytes)
    std::vector<uint8_t> header;
    if (!receiveData(header, 23)) {
        throw std::runtime_error("Failed to receive header");
    }

    // Parse payload size from header (bytes 19-22)
    uint32_t payloadSize = (header[19] << 24) |
                           (header[20] << 16) |
                           (header[21] << 8)  |
                           (header[22]);

    // Receive payload
    std::vector<uint8_t> payload;
    if (payloadSize > 0) {
        if (!receiveData(payload, payloadSize)) {
            throw std::runtime_error("Failed to receive payload");
        }
    }

    // Combine header+payload
    std::vector<uint8_t> response;
    response.reserve(23 + payloadSize);
    response.insert(response.end(), header.begin(), header.end());
    response.insert(response.end(), payload.begin(), payload.end());
    return response;
}
