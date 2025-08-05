// ProtocolBuilder.cpp
#include "ProtocolBuilder.h"

// -----------------------------------------------------------------------------
//  Helpers – little-endian writers
// -----------------------------------------------------------------------------
static void appendUint16LE(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>( v        & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8)  & 0xFF));
}

static void appendUint32LE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>( v        & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8)  & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

// -----------------------------------------------------------------------------
//  23-byte header builder
// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildHeader(
        const std::vector<uint8_t>& clientId,
        uint8_t  version,
        uint16_t code,
        uint32_t payloadSize)
{
    std::vector<uint8_t> header;
    header.insert(header.end(), clientId.begin(), clientId.end()); // 16
    header.push_back(version);                                     // 1
    appendUint16LE(header, code);                                  // 2
    appendUint32LE(header, payloadSize);                           // 4
    return header;                                                 // =23 bytes
}

// -----------------------------------------------------------------------------
// 600 – Register
// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildRegisterRequest(
        const std::string& username,
        const std::vector<uint8_t>& publicKeyDER)
{
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), username.begin(), username.end());
    payload.push_back(0);                               // null-terminator
    payload.insert(payload.end(), publicKeyDER.begin(), publicKeyDER.end());

    auto header = buildHeader(std::vector<uint8_t>(16, 0), 1, 600,
                              static_cast<uint32_t>(payload.size()));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildListRequest(
        const std::vector<uint8_t>& clientId)
{
    return buildHeader(clientId, 1, 601, 0);
}

// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildGetPublicKeyRequest(
        const std::vector<uint8_t>& clientId,
        const std::vector<uint8_t>& targetId)
{
    auto header = buildHeader(clientId, 1, 602,
                              static_cast<uint32_t>(targetId.size()));
    header.insert(header.end(), targetId.begin(), targetId.end());
    return header;
}

// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildFetchMessagesRequest(
        const std::vector<uint8_t>& clientId)
{
    return buildHeader(clientId, 1, 604, 0);
}

// -----------------------------------------------------------------------------
// 603 + msgType = 1  →  Request symmetric key (no content)
// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildRequestSymKey(
        const std::vector<uint8_t>& clientId,
        const std::vector<uint8_t>& targetId)
{
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), targetId.begin(), targetId.end()); // 16
    payload.push_back(1);                                            // type
    appendUint32LE(payload, 0);                                      // size=0

    auto header = buildHeader(clientId, 1, 603,
                              static_cast<uint32_t>(payload.size()));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

// -----------------------------------------------------------------------------
// 603 + msgType = 2  →  Send symmetric key
//    payload = targetId (16) + 2 + size (4) + encryptedSymKey
// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildSendSymKeyRequest(
        const std::vector<uint8_t>& clientId,
        const std::vector<uint8_t>& targetId,
        const std::vector<uint8_t>& encryptedSymKey)
{
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), targetId.begin(), targetId.end());     // 16
    payload.push_back(2);                                               // type
    appendUint32LE(payload,
                   static_cast<uint32_t>(encryptedSymKey.size()));      // size
    payload.insert(payload.end(),
                   encryptedSymKey.begin(), encryptedSymKey.end());     // data

    auto header = buildHeader(clientId, 1, 603,
                              static_cast<uint32_t>(payload.size()));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

// -----------------------------------------------------------------------------
// 603 + msgType = 3  →  Send text message
//    payload = targetId (16) + 3 + size (4) + (iv + ciphertext)
// -----------------------------------------------------------------------------
std::vector<uint8_t> ProtocolBuilder::buildSendTextRequest(
        const std::vector<uint8_t>& clientId,
        const std::vector<uint8_t>& targetId,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& ciphertext)
{
    std::vector<uint8_t> content;
    content.insert(content.end(), iv.begin(), iv.end());
    content.insert(content.end(), ciphertext.begin(), ciphertext.end());

    std::vector<uint8_t> payload;
    payload.insert(payload.end(), targetId.begin(), targetId.end());     // 16
    payload.push_back(3);                                               // type
    appendUint32LE(payload,
                   static_cast<uint32_t>(content.size()));              // size
    payload.insert(payload.end(), content.begin(), content.end());      // data

    auto header = buildHeader(clientId, 1, 603,
                              static_cast<uint32_t>(payload.size()));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}
