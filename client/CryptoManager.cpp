#include "CryptoManager.h"
#include <osrng.h>
#include <secblock.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
using namespace CryptoPP;

std::vector<uint8_t> CryptoManager::generateAESKey() const {
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());
    return std::vector<uint8_t>(key.begin(), key.end());
}

std::vector<uint8_t> CryptoManager::generateIV() const {
    AutoSeededRandomPool rng;
    SecByteBlock iv(AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());
    return std::vector<uint8_t>(iv.begin(), iv.end());
}

std::vector<uint8_t> CryptoManager::aesCBCEncrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv) const
{
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext.size() + AES::BLOCKSIZE);

    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key.data(), key.size(), iv.data());

    StreamTransformationFilter filter(encryption, new VectorSink(ciphertext));
    filter.Put(plaintext.data(), plaintext.size());
    filter.MessageEnd();

    return ciphertext;
}

std::vector<uint8_t> CryptoManager::aesCBCDecrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv) const
{
    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key.data(), key.size(), iv.data());

    StreamTransformationFilter filter(decryption, new VectorSink(plaintext));
    filter.Put(ciphertext.data(), ciphertext.size());
    filter.MessageEnd();

    return plaintext;
}
