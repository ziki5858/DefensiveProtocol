#pragma once

#include <vector>
#include <string>
#include <cstdint>

class ProtocolBuilder {
public:
    // Builds the 23-byte header:
    //   - clientId:     16 bytes
    //   - version:      1 byte
    //   - code:         2 bytes (big-endian)
    //   - payloadSize:  4 bytes (big-endian)
    static std::vector<uint8_t> buildHeader(
            const std::vector<uint8_t>& clientId,
            uint8_t version,
            uint16_t code,
            uint32_t payloadSize
    );

    // 600: Register → username\0 + publicKeyDER
    static std::vector<uint8_t> buildRegisterRequest(
            const std::string& username,
            const std::vector<uint8_t>& publicKeyDER
    );

    // 601: List clients (no payload)
    static std::vector<uint8_t> buildListRequest(
            const std::vector<uint8_t>& clientId
    );

    // 602: Get Public Key → payload = target Client ID (16 bytes)
    static std::vector<uint8_t> buildGetPublicKeyRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId
    );

    // 604: Fetch messages (no payload)
    static std::vector<uint8_t> buildFetchMessagesRequest(
            const std::vector<uint8_t>& clientId
    );

    // 603 + msgType=1: Request symmetric key
    // payload = [targetId (16)] + [msgType=1] + [contentSize=0]
    static std::vector<uint8_t> buildRequestSymKey(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId
    );

    // 603 + msgType=2: Send symmetric key
    // payload = [targetId (16)] + [msgType=2] + [contentSize] + [encryptedSymKey]
    static std::vector<uint8_t> buildSendSymKeyRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId,
            const std::vector<uint8_t>& encryptedSymKey
    );

    // 603 + msgType=3: Send text message
    // payload = [targetId (16)] + [msgType=3] + [contentSize] + [iv] + [ciphertext]
    static std::vector<uint8_t> buildSendTextRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& ciphertext
    );

    static std::vector<uint8_t> buildSendFileRequest(
            const std::vector<uint8_t>& fromId,
            const std::vector<uint8_t>& toId,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& cipherData
    );

};
