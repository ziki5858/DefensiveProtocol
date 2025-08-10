#pragma once

#include <vector>
#include <string>
#include <cstdint>

class ProtocolBuilder {
public:
    /* 23-byte header helper */
    static std::vector<uint8_t> buildHeader(
            const std::vector<uint8_t>& clientId,
            uint8_t                     version,
            uint16_t                    code,
            uint32_t                    payloadSize);

    /* 600 – register */
    static std::vector<uint8_t> buildRegisterRequest(
            const std::string&          username,
            const std::vector<uint8_t>& publicKeyDER);

    /* 601 – list clients */
    static std::vector<uint8_t> buildListRequest(
            const std::vector<uint8_t>& clientId);

    /* 602 – get public key */
    static std::vector<uint8_t> buildGetPublicKeyRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId);

    /* 604 – fetch messages */
    static std::vector<uint8_t> buildFetchMessagesRequest(
            const std::vector<uint8_t>& clientId);

    /* 603 – msgType 1 : request symmetric key */
    static std::vector<uint8_t> buildRequestSymKey(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId);

    /* 603 – msgType 2 : send symmetric key */
    static std::vector<uint8_t> buildSendSymKeyRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId,
            const std::vector<uint8_t>& encryptedSymKey);

    /* 603 – msgType 3 : send text (cipher only, IV = 0) */
    static std::vector<uint8_t> buildSendTextRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId,
            const std::vector<uint8_t>& ciphertext);

    /* 603 – msgType 4 : send file (cipher only, IV = 0) */
    static std::vector<uint8_t> buildSendFileRequest(
            const std::vector<uint8_t>& fromId,
            const std::vector<uint8_t>& toId,
            const std::vector<uint8_t>& cipherData);
};
