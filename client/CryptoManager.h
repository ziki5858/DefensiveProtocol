#include <vector>
#include <cstdint>

class CryptoManager {
public:
    // Generate random 128-bit AES key
    std::vector<uint8_t> generateAESKey() const;

    // Generate random 128-bit IV
    std::vector<uint8_t> generateIV() const;

    // AES-CBC encryption
    std::vector<uint8_t> aesCBCEncrypt(
            const std::vector<uint8_t>& plaintext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv) const;

    // AES-CBC decryption
    std::vector<uint8_t> aesCBCDecrypt(
            const std::vector<uint8_t>& ciphertext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv) const;
};
