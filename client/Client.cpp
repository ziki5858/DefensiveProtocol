#include "Client.h"
#include "ProtocolBuilder.h"
#include "ProtocolParser.h"
#include "aes.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

// bring in AES::BLOCKSIZE
using CryptoPP::AES;

// helper: bytes → hex
static std::string toHex(const std::vector<uint8_t>& b) {
    std::ostringstream oss;
    for (auto x : b) {
        oss << std::hex << std::setw(2) << std::setfill('0') << int(x);
    }
    return oss.str();
}
// helper: hex → bytes
static std::vector<uint8_t> hexToBytes(const std::string& s) {
    std::vector<uint8_t> v;
    v.reserve(s.size()/2);
    for (size_t i=0; i<s.size(); i+=2) {
        v.push_back(std::stoul(s.substr(i,2), nullptr, 16));
    }
    return v;
}

Client::Client()
        : connection(serverAddress, serverPort)
{
    readServerInfo();
    if (checkIfRegistered()) {
        loadMeInfo();
    }
}

void Client::run() {
    if (checkIfRegistered()) {
        std::cout << "Welcome back, your ID = " << toHex(clientId) << "\n";
    }
    while (true) {
        showMenu();
        int choice; std::cin >> choice;
        if (choice == 0) break;
        handleChoice(choice);
    }
}

void Client::readServerInfo() {
    std::ifstream f("server.info");
    if (!f) { std::cerr << "server.info not found\n"; exit(1); }
    std::string line; std::getline(f, line);
    auto p = line.find(':');
    serverAddress = line.substr(0,p);
    serverPort    = std::stoi(line.substr(p+1));
}

bool Client::checkIfRegistered() {
    std::ifstream f("me.info");
    return f.good();
}

void Client::loadMeInfo() {
    std::ifstream f("me.info");
    std::string name, hexid, pem;
    std::getline(f, name);
    std::getline(f, hexid);
    std::getline(f, pem);
    clientId      = hexToBytes(hexid);
    privateKeyPEM = pem;
}

void Client::saveMeInfo(const std::string& username) {
    std::ofstream f("me.info");
    f << username << "\n"
      << toHex(clientId) << "\n"
      << privateKeyPEM  << "\n";
}

void Client::showMenu() {
    std::cout <<
              "\nMessageU client:\n"
              "110) Register\n"
              "120) List clients\n"
              "130) Get public key\n"
              "140) Fetch messages\n"
              "150) Send text\n"
              "151) Request sym key\n"
              "152) Send sym key\n"
              "0) Exit\n"
              "? ";
}

void Client::handleChoice(int c) {
    switch(c) {
        case 110: registerUser();          break;
        case 120: requestClientsList();    break;
        case 130: requestPublicKey();      break;
        case 140: requestWaitingMessages();break;
        case 150: sendTextMessage();       break;
        case 151: requestSymmetricKey();   break;
        case 152: sendSymmetricKey();      break;
        default:  std::cout<<"Invalid choice\n";
    }
}

// ------------------------------------------------------------------
// 110) Register
void Client::registerUser() {
    std::cout << "Registration selected.\n";
    std::cout << "Enter username: ";
    std::string username; std::cin >> username;

    // 1) generate RSA and get public DER
    crypto.generateRSAKeyPair();
    auto pubDER = crypto.getPublicKeyDER();

    // 2) build & send
    auto req = ProtocolBuilder::buildRegisterRequest(username, pubDER);
    auto raw = connection.sendAndReceive(req);

    // 3) parse response
    auto resp = ProtocolParser::parse(raw);
    if (resp.code != 2100) {
        std::cerr << "Registration failed, code=" << resp.code << "\n";
        return;
    }

    // 4) extract ID + save
    clientId.assign(resp.payload.begin(), resp.payload.begin()+16);
    privateKeyPEM = crypto.getPrivateKeyPEM();
    saveMeInfo(username);

    std::cout << "Registered! Your ID=" << toHex(clientId) << "\n";
}

void Client::requestClientsList() {
    // 1) Build the request (601, no payload)
    auto request = ProtocolBuilder::buildListRequest(clientId);

    // 2) Send it and get raw response
    auto rawResponse = connection.sendAndReceive(request);

    // 3) Parse the response header + payload
    auto resp = ProtocolParser::parse(rawResponse);
    if (resp.code != 2101) {
        std::cerr << "Failed to get clients list, server code=" << resp.code << "\n";
        return;
    }

    // 4) Each record is 16-byte ID + 255-byte null-terminated name
    const size_t RECORD_SIZE = 16 + 255;
    size_t payloadSize = resp.payload.size();
    if (payloadSize % RECORD_SIZE != 0) {
        std::cerr << "Malformed clients list payload\n";
        return;
    }
    size_t count = payloadSize / RECORD_SIZE;

    std::cout << "Registered clients (" << count << "):\n";
    for (size_t i = 0; i < count; ++i) {
        auto baseIt = resp.payload.begin() + i * RECORD_SIZE;

        // extract ID
        std::vector<uint8_t> id(baseIt, baseIt + 16);
        std::ostringstream oss;
        for (auto b : id) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        std::string idHex = oss.str();

        // extract name (up to null terminator within next 255 bytes)
        std::string name;
        auto nameIt = baseIt + 16;
        for (size_t j = 0; j < 255; ++j) {
            char c = static_cast<char>(*(nameIt + j));
            if (c == '\0') break;
            name.push_back(c);
        }

        std::cout << "  - " << name << " (ID=" << idHex << ")\n";
    }
}

void Client::requestPublicKey() {
    // Prompt for target client ID (hex)
    std::cout << "Enter target client ID (hex): ";
    std::string hexId;
    std::cin >> hexId;
    auto targetId = hexToBytes(hexId);

    // Build and send the Get Public Key request (code 602)
    auto request = ProtocolBuilder::buildGetPublicKeyRequest(clientId, targetId);
    auto rawResponse = connection.sendAndReceive(request);

    // Parse the response
    auto resp = ProtocolParser::parse(rawResponse);
    if (resp.code != 2102) {
        std::cerr << "Failed to fetch public key, server code=" << resp.code << "\n";
        return;
    }

    // Response payload: [16-byte clientId] + [publicKey DER]
    std::vector<uint8_t> returnedId(resp.payload.begin(),
                                    resp.payload.begin() + 16);
    std::vector<uint8_t> pubKeyDER(resp.payload.begin() + 16,
                                   resp.payload.end());

    // Display the result
    std::cout << "Public key for ID " << toHex(returnedId) << ":\n"
              << toHex(pubKeyDER) << "\n";
}

void Client::requestWaitingMessages() {
    // 1) Build and send the fetch-messages request (code 604)
    auto request = ProtocolBuilder::buildFetchMessagesRequest(clientId);
    auto rawResponse = connection.sendAndReceive(request);

    // 2) Parse the response
    auto resp = ProtocolParser::parse(rawResponse);
    if (resp.code != 2104) {
        std::cerr << "Failed to fetch messages, server code=" << resp.code << "\n";
        return;
    }

    // 3) Iterate over each message in the payload:
    size_t idx = 0;
    while (idx < resp.payload.size()) {
        // a) Read sender ID (16 bytes)
        std::vector<uint8_t> fromId(resp.payload.begin() + idx,
                                    resp.payload.begin() + idx + 16);
        idx += 16;

        // b) Read message ID (4 bytes, big-endian) – we'll ignore it here
        uint32_t messageId = (resp.payload[idx] << 24) |
                             (resp.payload[idx+1] << 16) |
                             (resp.payload[idx+2] << 8) |
                             resp.payload[idx+3];
        idx += 4;

        // c) Read message type (1 byte)
        uint8_t msgType = resp.payload[idx++];

        // d) Read content size (4 bytes, big-endian)
        uint32_t contentSize = (resp.payload[idx] << 24) |
                               (resp.payload[idx+1] << 16) |
                               (resp.payload[idx+2] << 8) |
                               resp.payload[idx+3];
        idx += 4;

        // e) Extract content bytes
        std::vector<uint8_t> content(resp.payload.begin() + idx,
                                     resp.payload.begin() + idx + contentSize);
        idx += contentSize;

        // f) Decrypt/handle based on msgType
        std::string senderHex;
        {
            std::ostringstream oss;
            for (auto b : fromId) oss << std::hex << std::setw(2) << std::setfill('0') << int(b);
            senderHex = oss.str();
        }

        if (msgType == 1) {
            // Symmetric-key request
            std::cout << "[" << senderHex << "] requests your symmetric key\n";
        }
        else if (msgType == 2) {
            // Symmetric-key delivery
            // Decrypt with our RSA private key
            auto symKey = crypto.decryptRSA(content);
            // Store for this sender
            symKeyStore[senderHex] = symKey;
            std::cout << "Received symmetric key from " << senderHex << "\n";
        }
        else if (msgType == 3) {
            // Text message
            // First 16 bytes of content = IV
            std::vector<uint8_t> iv(content.begin(), content.begin()+AES::BLOCKSIZE);
            std::vector<uint8_t> cipher(content.begin()+AES::BLOCKSIZE, content.end());

            // Lookup symmetric key for this sender
            auto it = symKeyStore.find(senderHex);
            if (it == symKeyStore.end()) {
                std::cout << "[" << senderHex << "] sent a text but no key known, cannot decrypt\n";
            } else {
                auto plain = crypto.aesCBCDecrypt(cipher, it->second, iv);
                std::string text(plain.begin(), plain.end());
                std::cout << "[" << senderHex << "] says: " << text << "\n";
            }
        }
        else {
            std::cout << "Unknown message type " << int(msgType) << " from " << senderHex << "\n";
        }
    }
}

void Client::requestSymmetricKey() {
    // Prompt for target ID
    std::cout << "Enter target client ID (hex): ";
    std::string hexId;
    std::cin >> hexId;
    auto targetId = hexToBytes(hexId);

    // Build payload: [messageType=1] + targetId
    uint8_t messageType = 1;
    std::vector<uint8_t> payload;
    payload.push_back(messageType);
    payload.insert(payload.end(), targetId.begin(), targetId.end());

    // Build & send request (code 603)
    auto header = ProtocolBuilder::buildHeader(
            clientId,
            version,
            /* code */ 603,
            static_cast<uint32_t>(payload.size())
    );
    header.insert(header.end(), payload.begin(), payload.end());

    auto rawResponse = connection.sendAndReceive(header);
    auto resp = ProtocolParser::parse(rawResponse);

    // Expect 2103 (message stored)
    if (resp.code != 2103) {
        std::cerr << "Symmetric-key request failed, server code="
                  << resp.code << "\n";
        return;
    }

    std::cout << "Symmetric-key request sent successfully.\n";
}

void Client::sendSymmetricKey() {
    // 1) Prompt for target client ID (hex)
    std::cout << "Enter target client ID (hex): ";
    std::string hexId;
    std::cin >> hexId;
    auto targetId = hexToBytes(hexId);

    // 2) Fetch the peer’s public key from server (code 602)
    auto reqPub = ProtocolBuilder::buildGetPublicKeyRequest(clientId, targetId);
    auto rawPubResp = connection.sendAndReceive(reqPub);
    auto pubResp = ProtocolParser::parse(rawPubResp);
    if (pubResp.code != 2102) {
        std::cerr << "Failed to fetch public key, server code=" << pubResp.code << "\n";
        return;
    }
    // payload = [16-byte ID] + [publicKey DER]
    std::vector<uint8_t> peerPubDER(
            pubResp.payload.begin() + 16,
            pubResp.payload.end()
    );

    // 3) Generate a new AES key and store it locally
    auto symKey = crypto.generateAESKey();
    symKeyStore[hexId] = symKey;

    // 4) Encrypt the symmetric key with the peer’s RSA public key
    auto encSymKey = crypto.encryptRSA(symKey, peerPubDER);

    // 5) Build and send the “send symmetric key” request (code 603, msgType=2)
    auto req = ProtocolBuilder::buildSendSymKeyRequest(
            clientId,
            targetId,
            encSymKey
    );
    auto rawResp = connection.sendAndReceive(req);
    auto resp = ProtocolParser::parse(rawResp);
    if (resp.code != 2103) {
        std::cerr << "Failed to send symmetric key, server code=" << resp.code << "\n";
        return;
    }

    std::cout << "Symmetric key sent successfully.\n";
}

void Client::sendTextMessage() {
    // Prompt for target client ID in hex
    std::cout << "Enter target client ID (hex): ";
    std::string hexId;
    std::cin >> hexId;
    auto targetId = hexToBytes(hexId);

    // Prompt for message text
    std::cout << "Enter message: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string text;
    std::getline(std::cin, text);

    // Ensure we have a symmetric key for this peer
    auto it = symKeyStore.find(hexId);
    if (it == symKeyStore.end()) {
        std::cerr << "No symmetric key known for " << hexId << ". Request one first.\n";
        return;
    }
    auto symKey = it->second;

    // Generate a fresh IV and encrypt the plaintext
    auto iv = crypto.generateIV();
    std::vector<uint8_t> plainBytes(text.begin(), text.end());
    auto cipher = crypto.aesCBCEncrypt(plainBytes, symKey, iv);

    // Build and send the text message request (code 603, msgType=3)
    auto request = ProtocolBuilder::buildSendTextRequest(clientId, targetId, iv, cipher);
    auto rawResponse = connection.sendAndReceive(request);
    auto resp = ProtocolParser::parse(rawResponse);

    // Check for success (2103)
    if (resp.code != 2103) {
        std::cerr << "Failed to send text message, server code=" << resp.code << "\n";
        return;
    }

    std::cout << "Text message sent successfully.\n";
}
