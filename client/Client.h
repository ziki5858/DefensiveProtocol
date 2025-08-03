#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include "Connection.h"
#include "CryptoManager.h"
#include "ProtocolBuilder.h"
#include "ProtocolParser.h"

class Client {
public:
    Client();
    void run();

private:
    // network & crypto
    Connection    connection;   // socket connection
    CryptoManager crypto;       // handles AES/RSA

    // our identity (loaded/saved in me.info)
    std::vector<uint8_t> clientId;      // 16 bytes
    std::string          privateKeyPEM; // RSA priv key PEM
    uint8_t              version = 1;

    // store symmetric keys per-sender (key = sender-ID hex, value = AES key)
    std::unordered_map<std::string, std::vector<uint8_t>> symKeyStore;
    // cache of peers’ RSA public keys (hex ID → DER bytes)
    std::unordered_map<std::string, std::vector<uint8_t>> peerPubKeys;

    // server info
    std::string serverAddress;
    int         serverPort;

    // init / persistence
    void readServerInfo();
    bool checkIfRegistered();
    void loadMeInfo();
    void saveMeInfo(const std::string& username);

    // UI
    void showMenu();
    void handleChoice(int choice);

    // actions
    void registerUser();
    void requestClientsList();
    void requestPublicKey();
    void requestWaitingMessages();
    void sendTextMessage();
    void requestSymmetricKey();
    void sendSymmetricKey();
};
