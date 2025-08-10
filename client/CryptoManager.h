#pragma once
#include <vector>
#include <string>
#include <cstdint>

class CryptoManager {
public:
    // --- Symmetric (AES-CBC) ---
    std::vector<uint8_t> generateAESKey() const;
    std::vector<uint8_t> generateIV() const;
    std::vector<uint8_t> aesCBCEncrypt(const std::vector<uint8_t>& plain,
                                       const std::vector<uint8_t>& key) const;

    std::vector<uint8_t> aesCBCDecrypt(const std::vector<uint8_t>& cipher,
                                       const std::vector<uint8_t>& key) const;

    // --- Asymmetric (RSA 1024) ---
    void generateRSAKeyPair();
    std::vector<uint8_t> getPublicKeyDER() const;
    std::string           getPrivateKeyPEM() const;
    std::vector<uint8_t> encryptRSA(const std::vector<uint8_t>& data,
                                    const std::vector<uint8_t>& pubKeyDER) const;
    std::vector<uint8_t> decryptRSA(const std::vector<uint8_t>& cipher) const;


    ~CryptoManager();

private:
    void ensureRSA() const;
    void cleanupRSA();

    void* rsaPrivKey = nullptr;
};
