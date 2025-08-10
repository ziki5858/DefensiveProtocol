#include "CryptoManager.h"
#include <cryptlib.h>
#include <osrng.h>
#include <secblock.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <rsa.h>
#include <queue.h>
#include <base64.h>
#include <stdexcept>

using namespace CryptoPP;

// Zero IV for AES-CBC (16 bytes of 0)
static const std::vector<uint8_t> ZERO_IV(AES::BLOCKSIZE, 0x00);

// --- Symmetric (AES-CBC) ---

std::vector<uint8_t> CryptoManager::generateAESKey() const {
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());
    return { key.begin(), key.end() };
}

std::vector<uint8_t> CryptoManager::generateIV() const {
    AutoSeededRandomPool rng;
    SecByteBlock iv(AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());
    return { iv.begin(), iv.end() };
}

std::vector<uint8_t> CryptoManager::aesCBCEncrypt(
        const std::vector<uint8_t>& plain,
        const std::vector<uint8_t>& key) const
{
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), ZERO_IV.data());

    std::vector<uint8_t> out;
    StreamTransformationFilter f(enc, new VectorSink(out));
    f.Put(plain.data(), plain.size());
    f.MessageEnd();
    return out;
}

std::vector<uint8_t> CryptoManager::aesCBCDecrypt(
        const std::vector<uint8_t>& cipher,
        const std::vector<uint8_t>& key) const
{
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), ZERO_IV.data());

    std::vector<uint8_t> out;
    StreamTransformationFilter f(dec, new VectorSink(out));
    f.Put(cipher.data(), cipher.size());
    f.MessageEnd();
    return out;
}

// --- Asymmetric (RSA 1024) ---

void CryptoManager::generateRSAKeyPair() {
    cleanupRSA();
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024);
    rsaPrivKey = new RSA::PrivateKey(params);
}

std::vector<uint8_t> CryptoManager::getPublicKeyDER() const {
    ensureRSA();
    auto priv = reinterpret_cast<RSA::PrivateKey*>(rsaPrivKey);
    RSA::PublicKey pub(*priv);

    ByteQueue queue;
    pub.DEREncode(queue);
    std::vector<uint8_t> der(queue.CurrentSize());
    queue.Get(der.data(), der.size());
    return der;
}

std::string CryptoManager::getPrivateKeyPEM() const {
    ensureRSA();
    auto priv = reinterpret_cast<RSA::PrivateKey*>(rsaPrivKey);

    ByteQueue queue;
    priv->DEREncodePrivateKey(queue);

    std::string der(queue.CurrentSize(), '\0');
    queue.Get(reinterpret_cast<byte*>(&der[0]), der.size());

    std::string pem;
    StringSource ss(der, true,
                    new Base64Encoder(new StringSink(pem), false));
    return pem;
}

std::vector<uint8_t> CryptoManager::encryptRSA(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& pubKeyDER) const
{
    ByteQueue queue;
    queue.Put(pubKeyDER.data(), pubKeyDER.size());
    RSA::PublicKey pub;
    pub.BERDecode(queue);

    RSAES_PKCS1v15_Encryptor enc(pub);
    AutoSeededRandomPool rng;

    std::vector<uint8_t> cipher(enc.CiphertextLength(data.size()));
    enc.Encrypt(rng, data.data(), data.size(), cipher.data());
    return cipher;
}

std::vector<uint8_t> CryptoManager::decryptRSA(
        const std::vector<uint8_t>& cipher) const
{
    ensureRSA();
    auto priv = reinterpret_cast<RSA::PrivateKey*>(rsaPrivKey);

    RSAES_PKCS1v15_Decryptor dec(*priv);
    AutoSeededRandomPool rng;

    std::vector<uint8_t> recovered(dec.MaxPlaintextLength(cipher.size()));
    DecodingResult result = dec.Decrypt(rng,
                                        cipher.data(), cipher.size(),
                                        recovered.data());
    recovered.resize(result.messageLength);
    return recovered;
}

void CryptoManager::ensureRSA() const {
    if (!rsaPrivKey)
        throw std::runtime_error("RSA key not generated");
}

void CryptoManager::cleanupRSA() {
    if (rsaPrivKey) {
        delete reinterpret_cast<RSA::PrivateKey*>(rsaPrivKey);
        rsaPrivKey = nullptr;
    }
}

CryptoManager::~CryptoManager() {
    cleanupRSA();
}
