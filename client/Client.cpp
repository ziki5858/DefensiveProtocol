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

Client::Client() {
    readServerInfo();
    connection = std::make_unique<Connection>(serverAddress, serverPort);

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
              "153) Send file\n"
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
        case 153: sendFileMessage();     break;
        default:  std::cout<<"Invalid choice\n";
    }
}

// ------------------------------------------------------------------
// 110) Register
void Client::registerUser() {
    std::cout << "Registration selected.\n";
    std::cout << "Enter username: ";
    std::string username; std::cin >> username;

    crypto.generateRSAKeyPair();
    auto pubDER = crypto.getPublicKeyDER();
    auto req = ProtocolBuilder::buildRegisterRequest(username, pubDER);
    auto raw = connection->sendAndReceive(req);
    auto resp = ProtocolParser::parse(raw);

    if (resp.code != 2100) {
        std::cerr << "Registration failed, code=" << resp.code << "\n";
        return;
    }

    clientId.assign(resp.payload.begin(), resp.payload.begin()+16);
    privateKeyPEM = crypto.getPrivateKeyPEM();
    saveMeInfo(username);

    std::cout << "Registered! Your ID=" << toHex(clientId) << "\n";
}


void Client::requestClientsList() {
    // 1) Build the request (601, no payload)
    auto request = ProtocolBuilder::buildListRequest(clientId);

    // 2) Send it and get raw response
    auto rawResponse = connection->sendAndReceive(request);

    // 3) Parse the response header + payload
    auto resp = ProtocolParser::parse(rawResponse);
    if (resp.code != 2101) {
        std::cerr << "Failed to get clients list, server code = " << resp.code << "\n";
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
    clientsMap.clear();

    std::cout << "Registered clients (" << count << "):\n";
    for (size_t i = 0; i < count; ++i) {
        auto baseIt = resp.payload.begin() + i * RECORD_SIZE;

        // Extract ID
        std::vector<uint8_t> id(baseIt, baseIt + 16);

        // Extract name (null-terminated inside 255 bytes)
        std::string name;
        for (size_t j = 0; j < 255; ++j) {
            char c = static_cast<char>(*(baseIt + 16 + j));
            if (c == '\0') break;
            name.push_back(c);
        }

        // Save to map
        clientsMap[name] = id;

        // Show entry
        std::cout << "  - " << name << " (ID=" << toHex(id) << ")\n";
    }
}


void Client::requestPublicKey() {
    // Ask for username (not ID)
    std::cout << "Enter username: ";
    std::string username;
    std::cin >> username;

    // Check if username is known
    if (clientsMap.find(username) == clientsMap.end()) {
        std::cerr << "No such user in memory. Run option 120 first.\n";
        return;
    }

    // Get client ID for given username
    const std::vector<uint8_t>& targetId = clientsMap[username];

    // Build and send the request
    auto req = ProtocolBuilder::buildGetPublicKeyRequest(clientId, targetId);
    auto raw = connection->sendAndReceive(req);
    auto resp = ProtocolParser::parse(raw);

    if (resp.code != 2102) {
        std::cerr << "Server returned error code: " << resp.code << "\n";
        return;
    }

    // Payload = [16 bytes clientId] + [DER key]
    std::vector<uint8_t> returnedId(resp.payload.begin(), resp.payload.begin() + 16);
    std::vector<uint8_t> pubKeyDER(resp.payload.begin() + 16, resp.payload.end());

    std::string idHex = toHex(returnedId);
    peerPubKeys[idHex] = pubKeyDER;

    std::cout << "Public key for " << username << " (" << idHex << "):\n"
              << toHex(pubKeyDER) << "\n";
}

void Client::requestWaitingMessages() {
    // 1) Build and send the fetch-messages request (code 604)
    auto request     = ProtocolBuilder::buildFetchMessagesRequest(clientId);
    auto rawResponse = connection->sendAndReceive(request);
    auto resp        = ProtocolParser::parse(rawResponse);
    if (resp.code != 2104) {
        std::cerr << "Failed to fetch messages, server code=" << resp.code << "\n";
        return;
    }

    // 2) Iterate through the payload
    size_t idx = 0;
    while (idx < resp.payload.size()) {
        // a) Read sender ID (16 bytes)
        std::vector<uint8_t> fromId(
                resp.payload.begin() + idx,
                resp.payload.begin() + idx + 16
        );
        idx += 16;

        // b) Read message ID (4 bytes, little-endian)
        uint32_t messageId =  resp.payload[idx]
                              | (resp.payload[idx + 1] << 8)
                              | (resp.payload[idx + 2] << 16)
                              | (resp.payload[idx + 3] << 24);
        idx += 4;

        // c) Read msgType (1 byte)
        uint8_t msgType = resp.payload[idx++];

        // d) Read content size (4 bytes, little-endian)
        uint32_t contentSize =  resp.payload[idx]
                                | (resp.payload[idx + 1] << 8)
                                | (resp.payload[idx + 2] << 16)
                                | (resp.payload[idx + 3] << 24);
        idx += 4;

        // e) Extract content bytes
        std::vector<uint8_t> content(
                resp.payload.begin() + idx,
                resp.payload.begin() + idx + contentSize
        );
        idx += contentSize;

        // f) Convert sender ID to hex string
        std::ostringstream oss;
        for (auto b : fromId) {
            oss << std::hex << std::setw(2) << std::setfill('0') << int(b);
        }
        std::string senderHex = oss.str();

        // g) Handle based on msgType
        if (msgType == 1) {
            // Symmetric-key request
            std::cout << "[" << senderHex << "] requests your symmetric key\n";
        }
        else if (msgType == 2) {
            // Symmetric-key delivery
            auto symKey = crypto.decryptRSA(content);
            symKeyStore[senderHex] = symKey;
            std::cout << "Received symmetric key from " << senderHex << "\n";
        }
        else if (msgType == 3) {
            // Text message: first 16 bytes = IV
            std::vector<uint8_t> iv(content.begin(), content.begin() + AES::BLOCKSIZE);
            std::vector<uint8_t> cipher(content.begin() + AES::BLOCKSIZE, content.end());
            auto it = symKeyStore.find(senderHex);
            if (it == symKeyStore.end()) {
                std::cout << "[" << senderHex << "] sent a text but no key known, cannot decrypt\n";
            } else {
                auto plain = crypto.aesCBCDecrypt(cipher, it->second, iv);
                std::string text(plain.begin(), plain.end());
                std::cout << "[" << senderHex << "] says: " << text << "\n";
            }
        }
        else if (msgType == 4) {
            // File message: first AES::BLOCKSIZE bytes = IV
            std::vector<uint8_t> iv(
                    content.begin(),
                    content.begin() + AES::BLOCKSIZE
            );
            std::vector<uint8_t> cipher(
                    content.begin() + AES::BLOCKSIZE,
                    content.end()
            );

            auto it = symKeyStore.find(senderHex);
            if (it == symKeyStore.end()) {
                std::cout << "No symmetric key to decrypt file from " << senderHex << "\n";
            } else {
                // decrypt and save to disk
                auto plain = crypto.aesCBCDecrypt(cipher, it->second, iv);
                std::string fname = "received_from_" + senderHex + ".dat";
                std::ofstream out(fname, std::ios::binary);
                out.write(reinterpret_cast<const char*>(plain.data()), plain.size());
                out.close();
                std::cout << "Saved file to " << fname << "\n";
            }
        }

        else {
            // Unknown type
            std::cout << "Unknown message type " << int(msgType)
                      << " from " << senderHex << "\n";
        }
    }
}


void Client::requestSymmetricKey() {
    // 1) Prompt for recipient username
    std::cout << "Enter recipient username: ";
    std::string username;
    std::cin >> username;

    // 2) Lookup client ID
    if (clientsMap.find(username) == clientsMap.end()) {
        std::cerr << "No such user in memory. Run option 120 first.\n";
        return;
    }
    const auto& targetId = clientsMap[username];

    // 3) Build & send the "request sym key" message
    auto req = ProtocolBuilder::buildRequestSymKey(clientId, targetId);
    auto raw = connection->sendAndReceive(req);

    // 4) Parse and check response
    auto resp = ProtocolParser::parse(raw);
    if (resp.code != 2103) {
        std::cerr << "Symmetric-key request failed, server code="
                  << resp.code << "\n";
        return;
    }

    std::cout << "Symmetric-key request sent successfully.\n";
}


void Client::sendSymmetricKey() {
    // 1. Prompt for recipient username
    std::cout << "Enter recipient username: ";
    std::string username;
    std::cin >> username;
    if (!clientsMap.count(username)) {
        std::cerr << "Error: No such user in memory. Please run option 120 first.\n";
        return;
    }
    auto targetId = clientsMap[username];

    // 2. Request peer’s public key (code 602)
    auto reqPub = ProtocolBuilder::buildGetPublicKeyRequest(clientId, targetId);
    auto rawPubResp = connection->sendAndReceive(reqPub);
    auto pubResp = ProtocolParser::parse(rawPubResp);
    if (pubResp.code != 2102) {
        std::cerr << "Error: Failed to fetch public key, server code=" << pubResp.code << "\n";
        return;
    }
    // Extract DER‐encoded public key (skip 16‐byte header)
    std::vector<uint8_t> peerPubDER(pubResp.payload.begin() + 16, pubResp.payload.end());

    // 3. Generate AES key and store it
    auto symKey = crypto.generateAESKey();
    std::string hexId = toHex(targetId);
    symKeyStore[hexId] = symKey;

    // 4. Encrypt AES key with peer’s RSA public key
    auto encSymKey = crypto.encryptRSA(symKey, peerPubDER);

    // Debug: ensure encrypted key is non-empty
    std::cout << "[DEBUG] EncryptedSymKey size: " << encSymKey.size() << "\n";
    if (encSymKey.empty()) {
        std::cerr << "Error: encryptedSymKey is empty, aborting send.\n";
        return;
    }

    // 5. Build send-sym-key request (code 603 + msgType=2)
    auto reqBytes = ProtocolBuilder::buildSendSymKeyRequest(
            clientId,
            targetId,
            encSymKey
    );

    // Debug: show total bytes including header + payload
    std::cout << "[DEBUG] Will send " << reqBytes.size()
              << " bytes (payload=" << encSymKey.size() << ")\n";

    // 6. Send and receive in one shot
    auto rawResp = connection->sendAndReceive(reqBytes);
    auto resp    = ProtocolParser::parse(rawResp);
    if (resp.code != 2103) {
        std::cerr << "Error: Failed to send symmetric key, server code=" << resp.code << "\n";
        return;
    }

    std::cout << "Symmetric key sent successfully.\n";
}


void Client::sendTextMessage() {
    // Prompt for recipient username
    std::cout << "Enter recipient username: ";
    std::string username;
    std::cin >> username;

    // Lookup target ID from clientsMap
    if (!clientsMap.count(username)) {
        std::cerr << "No such user in memory. Run option 120 first.\n";
        return;
    }

    auto targetId = clientsMap[username];
    std::string hexId = toHex(targetId);

    // Prompt for message text
    std::cout << "Enter message: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string text;
    std::getline(std::cin, text);

    // Ensure we have a symmetric key for this peer
    auto it = symKeyStore.find(hexId);
    if (it == symKeyStore.end()) {
        std::cerr << "No symmetric key known for " << username << ". Request one first.\n";
        return;
    }
    auto symKey = it->second;

    // Generate a fresh IV and encrypt the plaintext
    auto iv = crypto.generateIV();
    std::vector<uint8_t> plainBytes(text.begin(), text.end());
    auto cipher = crypto.aesCBCEncrypt(plainBytes, symKey, iv);

    // Build and send the text message request (code 603, msgType=3)
    auto request = ProtocolBuilder::buildSendTextRequest(clientId, targetId, iv, cipher);
    auto rawResponse = connection->sendAndReceive(request);
    auto resp = ProtocolParser::parse(rawResponse);

    // Check for success (2103)
    if (resp.code != 2103) {
        std::cerr << "Failed to send text message, server code=" << resp.code << "\n";
        return;
    }

    std::cout << "Text message sent successfully.\n";
}

void Client::sendFileMessage() {
    // 1. Prompt for recipient username
    std::cout << "Enter recipient username: ";
    std::string username;
    std::cin >> username;
    if (!clientsMap.count(username)) {
        std::cerr << "No such user. Run option 120 first.\n";
        return;
    }
    auto targetId = clientsMap[username];
    std::string hexId = toHex(targetId);

    // 2. Ensure we have a symmetric key for this peer
    auto it = symKeyStore.find(hexId);
    if (it == symKeyStore.end()) {
        std::cerr << "No symmetric key for " << username << ". Request one first.\n";
        return;
    }
    auto symKey = it->second;

    // 3. Read file path and load into byte vector
    std::cout << "Enter file path: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string path;
    std::getline(std::cin, path);
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open file: " << path << "\n";
        return;
    }
    std::vector<uint8_t> fileBytes{
            std::istreambuf_iterator<char>(in),
            std::istreambuf_iterator<char>()
    };

    // 4. Generate a fresh IV and encrypt the file bytes with AES-CBC
    auto iv     = crypto.generateIV();
    auto cipher = crypto.aesCBCEncrypt(fileBytes, symKey, iv);

    // 5. Build the 603 packet
    auto req = ProtocolBuilder::buildSendFileRequest(
            clientId,   // fromId (ignored by builder)
            targetId,   // toId
            iv,
            cipher
    );

    // 6. Send and receive the server response
    auto rawResp = connection->sendAndReceive(req);
    auto resp    = ProtocolParser::parse(rawResp);
    if (resp.code != 2103) {
        std::cerr << "Failed to send file, server code = " << resp.code << "\n";
        return;
    }

    std::cout << "File sent successfully.\n";
}
