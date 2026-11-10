
#include "Crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <stdexcept>
#include <memory>
#include <limits>

using namespace std;

namespace {
    constexpr int KEY_SIZE = 32;
    constexpr int SALT_SIZE = 16;
    constexpr int NONCE_SIZE = 12;
    constexpr int TAG_SIZE = 16;
    constexpr int PBKDF2_ITERATIONS = 600000;

    vector<unsigned char> deriveKey(
        const string& masterPassword,
        const vector<unsigned char>& salt
    ) {
        if (masterPassword.empty() || salt.size() != SALT_SIZE) {
            throw invalid_argument("Invalid master password or salt!");
        }

        vector<unsigned char> key(KEY_SIZE);

        int result = PKCS5_PBKDF2_HMAC(
            masterPassword.data(),
            static_cast<int>(masterPassword.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            PBKDF2_ITERATIONS,
            EVP_sha256(),
            KEY_SIZE,
            key.data()
        );

        if (result != 1) {
            throw runtime_error("Key derivation failed!");
        }

        return key;
    }

    void generateRandom(
        vector<unsigned char>& buffer
    ) {
        if (buffer.empty()) {
            throw invalid_argument("Random buffer cannot be empty!");
        }

        if (RAND_bytes(
                buffer.data(),
                static_cast<int>(buffer.size())
            ) != 1) {
            throw runtime_error("Secure random generation failed!");
        }
    }
}

EncryptedData Crypto::encrypt(
    const string& plaintext,
    const string& masterPassword
) {
    if (plaintext.empty()) {
        throw invalid_argument("Cannot encrypt empty data!");
    }

    if (plaintext.size() >
        static_cast<size_t>(numeric_limits<int>::max())) {
        throw invalid_argument("Data is too large!");
    }

    EncryptedData data;

    data.salt.resize(SALT_SIZE);
    data.nonce.resize(NONCE_SIZE);
    data.authTag.resize(TAG_SIZE);

    generateRandom(data.salt);
    generateRandom(data.nonce);

    vector<unsigned char> key =
        deriveKey(masterPassword, data.salt);

    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!context) {
        OPENSSL_cleanse(key.data(), key.size());
        throw runtime_error("Encryption context creation failed!");
    }

    data.ciphertext.resize(plaintext.size() + 16);

    int length = 0;
    int totalLength = 0;

    bool success =
        EVP_EncryptInit_ex(
            context.get(),
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr
        ) == 1 &&

        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            NONCE_SIZE,
            nullptr
        ) == 1 &&

        EVP_EncryptInit_ex(
            context.get(),
            nullptr,
            nullptr,
            key.data(),
            data.nonce.data()
        ) == 1 &&

        EVP_EncryptUpdate(
            context.get(),
            data.ciphertext.data(),
            &length,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())
        ) == 1;

    if (success) {
        totalLength = length;

        success = EVP_EncryptFinal_ex(
            context.get(),
            data.ciphertext.data() + totalLength,
            &length
        ) == 1;
    }

    if (success) {
        totalLength += length;
        data.ciphertext.resize(totalLength);

        success = EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_GET_TAG,
            TAG_SIZE,
            data.authTag.data()
        ) == 1;
    }

    OPENSSL_cleanse(key.data(), key.size());

    if (!success) {
        throw runtime_error("Encryption failed!");
    }

    return data;
}

string Crypto::decrypt(
    const EncryptedData& data,
    const string& masterPassword
) {
    if (data.salt.size() != SALT_SIZE ||
        data.nonce.size() != NONCE_SIZE ||
        data.authTag.size() != TAG_SIZE ||
        data.ciphertext.empty()) {
        throw invalid_argument("Invalid encrypted data!");
    }

    if (data.ciphertext.size() >
        static_cast<size_t>(numeric_limits<int>::max())) {
        throw invalid_argument("Encrypted data is too large!");
    }

    vector<unsigned char> key =
        deriveKey(masterPassword, data.salt);

    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!context) {
        OPENSSL_cleanse(key.data(), key.size());
        throw runtime_error("Decryption context creation failed!");
    }

    vector<unsigned char> plaintext(data.ciphertext.size() + 16);

    int length = 0;
    int totalLength = 0;

    bool success =
        EVP_DecryptInit_ex(
            context.get(),
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr
        ) == 1 &&

        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            NONCE_SIZE,
            nullptr
        ) == 1 &&

        EVP_DecryptInit_ex(
            context.get(),
            nullptr,
            nullptr,
            key.data(),
            data.nonce.data()
        ) == 1 &&

        EVP_DecryptUpdate(
            context.get(),
            plaintext.data(),
            &length,
            data.ciphertext.data(),
            static_cast<int>(data.ciphertext.size())
        ) == 1;

    if (success) {
        totalLength = length;

        success = EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_TAG,
            TAG_SIZE,
            const_cast<unsigned char*>(data.authTag.data())
        ) == 1;
    }

    if (success) {
        success = EVP_DecryptFinal_ex(
            context.get(),
            plaintext.data() + totalLength,
            &length
        ) == 1;
    }

    OPENSSL_cleanse(key.data(), key.size());

    if (!success) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw runtime_error(
            "Decryption failed! Wrong master password or corrupted data."
        );
    }

    totalLength += length;
    plaintext.resize(totalLength);

    string result(
        reinterpret_cast<const char*>(plaintext.data()),
        plaintext.size()
    );

    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    return result;
}
