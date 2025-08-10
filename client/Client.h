#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include "Connection.h"
#include "CryptoManager.h"
#include "ProtocolBuilder.h"
#include "ProtocolParser.h"

class Client {
public:
    Client();
    void run();

private:
    /* ─── Network & crypto ─────────────────────────── */
    std::unique_ptr<Connection> connection;
    CryptoManager               crypto;           // AES / RSA helpers

    /* ─── Our identity ─────────────────────────────── */
    std::vector<uint8_t> clientId;      // 16-byte ID assigned by server
    std::string          privateKeyPEM; // RSA private key (PEM)
    uint8_t              version = 2;   // protocol version

    /* ─── In-memory caches ─────────────────────────── */
    // peer symmetric keys   (hex-ID → AES key)
    std::unordered_map<std::string,std::vector<uint8_t>> symKeyStore;
    // peer RSA public keys  (hex-ID → DER bytes)
    std::unordered_map<std::string,std::vector<uint8_t>> peerPubKeys;
    // users list            (username → client ID bytes)
    std::unordered_map<std::string,std::vector<uint8_t>> clientsMap;
    // ID → name mapping for nicer printouts
    std::unordered_map<std::string,std::string>          idToName;

    /* ─── Server info ──────────────────────────────── */
    std::string serverAddress;
    int         serverPort;

    /* ─── Init & persistence ───────────────────────── */
    void readServerInfo();
    bool checkIfRegistered();
    void loadMeInfo();
    void saveMeInfo(const std::string& username);

    /* ─── Menu helpers ─────────────────────────────── */
    static void showMenu();
    void handleChoice(int choice);

    /* ─── Actions ──────────────────────────────────── */
    void registerUser();
    void requestClientsList();
    void requestPublicKey();
    void requestWaitingMessages();
    void sendTextMessage();
    void requestSymmetricKey();
    void sendSymmetricKey();
    void sendFileMessage();
};
