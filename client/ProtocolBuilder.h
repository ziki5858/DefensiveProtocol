#include <vector>
#include <string>
#include <cstdint>

class ProtocolBuilder {
public:
    // Builds the 23-byte header:
    // - clientId: 16 bytes
    // - version: 1 byte
    // - code: 2 bytes (big-endian)
    // - payloadSize: 4 bytes (big-endian)
    static std::vector<uint8_t> buildHeader(
            const std::vector<uint8_t>& clientId,
            uint8_t version,
            uint16_t code,
            uint32_t payloadSize
    );

    // Register request: username (null-terminated ASCII, max 255 bytes) + public key DER
    static std::vector<uint8_t> buildRegisterRequest(
            const std::string& username,
            const std::vector<uint8_t>& publicKeyDER
    );

    // List clients request (code 601), payloadSize=0
    static std::vector<uint8_t> buildListRequest(const std::vector<uint8_t>& clientId);

    // Get Public Key request (code 602), payload: target Client ID (16 bytes)
    static std::vector<uint8_t> buildGetPublicKeyRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId
    );

    // Fetch Messages request (code 604), payloadSize=0
    static std::vector<uint8_t> buildFetchMessagesRequest(
            const std::vector<uint8_t>& clientId
    );

    // Send Symmetric Key request (code 1 message type within 603), payload: targetId + encryptedSymKey
    static std::vector<uint8_t> buildSendSymKeyRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId,
            const std::vector<uint8_t>& encryptedSymKey
    );

    // Send Text Message request (code 3 message type within 603), payload: targetId + IV + ciphertext
    static std::vector<uint8_t> buildSendTextRequest(
            const std::vector<uint8_t>& clientId,
            const std::vector<uint8_t>& targetId,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& ciphertext
    );
};
