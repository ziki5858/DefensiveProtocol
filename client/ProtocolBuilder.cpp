// ProtocolBuilder.cpp
#include "ProtocolBuilder.h"

// Helpers to append big-endian integers
static void appendUint16BE(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(uint8_t((v >> 8) & 0xFF));
    buf.push_back(uint8_t(v & 0xFF));
}

static void appendUint32BE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(uint8_t((v >> 24) & 0xFF));
    buf.push_back(uint8_t((v >> 16) & 0xFF));
    buf.push_back(uint8_t((v >> 8) & 0xFF));
    buf.push_back(uint8_t(v & 0xFF));
}

// Build the 23-byte header
std::vector<uint8_t> ProtocolBuilder::buildHeader(
        const std::vector<uint8_t>& clientId,
        uint8_t version,
        uint16_t code,
        uint32_t payloadSize
) {
    std::vector<uint8_t> header;
    // Client ID (16 bytes)
    header.insert(header.end(), clientId.begin(), clientId.end());
    // Version (1 byte)
    header.push_back(version);
    // Code (2 bytes)
    appendUint16BE(header, code);
    // Payload size (4 bytes)
    appendUint32BE(header, payloadSize);
    return header;
}

// Register (600): username\0 + publicKeyDER
std::vector<uint8_t> ProtocolBuilder::buildRegisterRequest(
        const std::string& username,
        const std::vector<uint8_t>& publicKeyDER
) {
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), username.begin(), username.end());
    payload.push_back(0);
    payload.insert(payload.end(), publicKeyDER.begin(), publicKeyDER.end());

    auto header = buildHeader(
            /*clientId*/ std::vector<uint8_t>(16, 0),
            /*version*/ 1,
            /*code*/ 600,
                         static_cast<uint32_t>(payload.size())
    );
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

// List clients (601): no payload
std::vector<uint8_t> ProtocolBuilder::buildListRequest(
        const std::vector<uint8_t>& clientId
) {
    auto header = buildHeader(clientId, 1, 601, 0);
    return header;
}

// Get Public Key (602): payload = targetId (16 bytes)
std::vector<uint8_t> ProtocolBuilder::buildGetPublicKeyRequest(
        const std::vector<uint8_t>& clientId,
        const std::vector<uint8_t>& targetId
) {
    uint32_t payloadSize = static_cast<uint32_t>(targetId.size());
    auto header = buildHeader(clientId, 1, 602, payloadSize);
    header.insert(header.end(), targetId.begin(), targetId.end());
    return header;
}

// Fetch Messages (604): no payload
std::vector<uint8_t> ProtocolBuilder::buildFetchMessagesRequest(
        const std::vector<uint8_t>& clientId
) {
    auto header = buildHeader(clientId, 1, 604, 0);
    return header;
}

// Send Symmetric Key (603, msg type=2): [type=2] + targetId + encryptedSymKey
std::vector<uint8_t> ProtocolBuilder::buildSendSymKeyRequest(
        const std::vector<uint8_t>& clientId,
        const std::vector<uint8_t>& targetId,
        const std::vector<uint8_t>& encryptedSymKey
) {
    std::vector<uint8_t> payload;
    payload.push_back(2);
    payload.insert(payload.end(), targetId.begin(), targetId.end());
    payload.insert(payload.end(), encryptedSymKey.begin(), encryptedSymKey.end());

    auto header = buildHeader(clientId, 1, 603, static_cast<uint32_t>(payload.size()));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

// Send Text Message (603, msg type=3): [type=3] + targetId + iv + ciphertext
std::vector<uint8_t> ProtocolBuilder::buildSendTextRequest(
        const std::vector<uint8_t>& clientId,
        const std::vector<uint8_t>& targetId,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& ciphertext
) {
    std::vector<uint8_t> payload;
    payload.push_back(3);
    payload.insert(payload.end(), targetId.begin(), targetId.end());
    payload.insert(payload.end(), iv.begin(), iv.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

    auto header = buildHeader(clientId, 1, 603, static_cast<uint32_t>(payload.size()));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}
