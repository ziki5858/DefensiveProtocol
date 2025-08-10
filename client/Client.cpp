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
              "\nMessageU client at your service.\n\n"
              "110) Register\n"
              "120) Request for clients list\n"
              "130) Request for public key\n"
              "140) Request for waiting messages\n"
              "150) Send a text message\n"
              "151) Send a request for symmetric key\n"
              "152) Send your symmetric key\n"
              "153) Send a file\n"
              "0) Exit client\n"
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
        case 0:
            exit(0);
        default:  std::cout<<"Invalid choice\n";
    }
}


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
    auto request = ProtocolBuilder::buildListRequest(clientId);
    auto rawResponse = connection->sendAndReceive(request);
    auto resp = ProtocolParser::parse(rawResponse);

    if (resp.code != 2101) {
        std::cout << "server responded with an error\n";
        return;
    }

    const size_t RECORD_SIZE = 16 + 255;
    size_t payloadSize = resp.payload.size();
    if (payloadSize % RECORD_SIZE != 0) {
        std::cerr << "Malformed clients list payload\n";
        return;
    }

    size_t count = payloadSize / RECORD_SIZE;
    clientsMap.clear();

    if (count == 0) {
        std::cout << "No other clients registered.\n";
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        auto baseIt = resp.payload.begin() + i * RECORD_SIZE;

        std::vector<uint8_t> id(baseIt, baseIt + 16);

        std::string name;
        for (size_t j = 0; j < 255; ++j) {
            char c = static_cast<char>(*(baseIt + 16 + j));
            if (c == '\0') break;
            name.push_back(c);
        }

        clientsMap[name] = id;
        std::cout << name << "\n"; // print only the name
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
    auto req  = ProtocolBuilder::buildFetchMessagesRequest(clientId);
    auto resp = ProtocolParser::parse(connection->sendAndReceive(req));
    if (resp.code != 2104) {
        std::cout << "server responded with an error\n";
        return;
    }

    size_t i = 0;
    while (i < resp.payload.size()) {
        std::vector<uint8_t> fromId(resp.payload.begin()+i, resp.payload.begin()+i+16); i += 16;

        uint32_t msgId =  resp.payload[i] | (resp.payload[i+1]<<8)
                          | (resp.payload[i+2]<<16) | (resp.payload[i+3]<<24); i += 4;

        uint8_t  type  = resp.payload[i++];
        uint32_t len   =  resp.payload[i] | (resp.payload[i+1]<<8)
                          | (resp.payload[i+2]<<16) | (resp.payload[i+3]<<24); i += 4;

        std::vector<uint8_t> content(resp.payload.begin()+i, resp.payload.begin()+i+len); i += len;

        std::string senderHex = toHex(fromId);
        const std::string& who = idToName.count(senderHex) ? idToName[senderHex] : senderHex;

        if (type == 1) {
            // Symmetric key request
            std::cout << "Request for symmetric key\n";
        }
        else if (type == 2) {
            // Symmetric key received
            symKeyStore[senderHex] = crypto.decryptRSA(content);
            std::cout << "symmetric key received\n";
        }
        else if (type == 3) { // Text message
            if (!symKeyStore.count(senderHex)) {
                std::cout << "can't decrypt message\n";
                continue;
            }
            auto plain = crypto.aesCBCDecrypt(content, symKeyStore[senderHex]);
            std::cout << "From: " << who << "\n";
            std::cout << "Content:\n";
            std::cout << std::string(plain.begin(), plain.end()) << "\n";
            std::cout << "-----<EOM>-----\n\n";
        }
        else if (type == 4) { // File message (bonus)
            if (!symKeyStore.count(senderHex)) {
                std::cout << "can't decrypt message\n";
                continue;
            }
            auto plain = crypto.aesCBCDecrypt(content, symKeyStore[senderHex]);
            auto tmp   = std::filesystem::temp_directory_path();
            std::string fname = (tmp / ("msgu_" + senderHex + ".bin")).string();
            std::ofstream(fname, std::ios::binary).write(reinterpret_cast<char*>(plain.data()), plain.size());
            std::cout << fname << '\n';
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
        std::cout << "server responded with an error\n";
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

    // 6. Send and receive in one shot
    auto rawResp = connection->sendAndReceive(reqBytes);
    auto resp    = ProtocolParser::parse(rawResp);
    if (resp.code != 2103) {
        std::cout << "server responded with an error\n";
        return;
    }

    std::cout << "Symmetric key sent successfully.\n";
}


void Client::sendTextMessage()
{
    /* 1. choose recipient */
    std::cout << "Enter recipient username: ";
    std::string username;
    std::cin >> username;

    if (!clientsMap.count(username)) {
        std::cerr << "No such user in memory.  Run option 120 first.\n";
        return;
    }
    auto  targetId = clientsMap[username];
    auto  hexId    = toHex(targetId);

    /* 2. read plaintext */
    std::cout << "Enter message: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string text;
    std::getline(std::cin, text);
    std::vector<uint8_t> plainBytes(text.begin(), text.end());

    /* 3. fetch symmetric key */
    auto it = symKeyStore.find(hexId);
    if (it == symKeyStore.end()) {
        std::cerr << "No symmetric key for " << username
                  << ".  Request one first.\n";
        return;
    }
    const auto& symKey = it->second;

    /* 4. encrypt (IV = 0 internally) */
    auto cipher = crypto.aesCBCEncrypt(plainBytes, symKey);

    /* 5. build & send request */
    auto request     =
            ProtocolBuilder::buildSendTextRequest(clientId, targetId, cipher);
    auto rawResponse = connection->sendAndReceive(request);
    auto resp        = ProtocolParser::parse(rawResponse);

    if (resp.code != 2103) {
        std::cout << "server responded with an error\n";
        return;
    }
    std::cout << "Text message sent successfully.\n";
}


void Client::sendFileMessage() {
    std::cout << "Enter recipient username: ";
    std::string user; std::cin >> user;
    if (!clientsMap.count(user)) {
        std::cerr << "Unknown user.\n";
        return;
    }
    auto targetId = clientsMap[user];
    std::string hexId = toHex(targetId);

    if (!symKeyStore.count(hexId)) {
        std::cerr << "No symmetric key – request one first.\n";
        return;
    }
    auto symKey = symKeyStore[hexId];

    std::cout << "Enter file path: ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string path; std::getline(std::cin, path);
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cout << "file not found\n";
        return;
    }
    std::vector<uint8_t> bytes{ std::istreambuf_iterator<char>(in), {} };

    auto cipher = crypto.aesCBCEncrypt(bytes, symKey); // IV = 0
    auto req = ProtocolBuilder::buildSendFileRequest(clientId, targetId, cipher);
    auto resp = ProtocolParser::parse(connection->sendAndReceive(req));
    if (resp.code != 2103) {
        std::cout << "server responded with an error\n";
        return;
    }
}

