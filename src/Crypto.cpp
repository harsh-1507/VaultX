#include "Crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <limits>
#include <memory>
#include <stdexcept>

using namespace std;

namespace {

constexpr int KEY_SIZE = 32;
constexpr int SALT_SIZE = 16;
constexpr int NONCE_SIZE = 12;
constexpr int TAG_SIZE = 16;
constexpr int PBKDF2_ITERATIONS = 600000;

constexpr size_t MAX_AAD_SIZE = 1024;

using Context = unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

// Feeds the additional authenticated data into the GCM state (before the data).
bool addAad(EVP_CIPHER_CTX* context, const Bytes& aad, bool encrypting) {
    if (aad.empty()) return true;

    int length = 0;
    const int size = static_cast<int>(aad.size());

    return encrypting ? EVP_EncryptUpdate(context, nullptr, &length, aad.data(), size) == 1
                      : EVP_DecryptUpdate(context, nullptr, &length, aad.data(), size) == 1;
}

void fillRandom(Bytes& buffer) {
    if (buffer.empty() ||
        RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1)
        throw runtime_error("Secure random generation failed!");
}

}  // namespace

// ------------------------------------------------------------ Cipher (base)
// `key` is a Bytes, whose allocator wipes the buffer when it is destroyed, so
// the key is erased on every exit path (return or exception) without extra code.
EncryptedData Cipher::encrypt(const string& plaintext, const string& password,
                              const Bytes& aad) const {
    Bytes salt = randomSalt();
    Bytes key = deriveKey(password, salt);
    return encryptWithKey(plaintext, key, salt, aad);
}

string Cipher::decrypt(const EncryptedData& data, const string& password,
                       const Bytes& aad) const {
    Bytes key = deriveKey(password, data.salt);
    return decryptWithKey(data, key, aad);
}

// ------------------------------------------------------------ AesGcmCipher
Bytes AesGcmCipher::randomSalt() const {
    Bytes salt(SALT_SIZE);
    fillRandom(salt);
    return salt;
}

Bytes AesGcmCipher::deriveKey(const string& password, const Bytes& salt) const {
    if (password.empty() || salt.size() != SALT_SIZE)
        throw invalid_argument("Invalid master password or salt!");

    Bytes key(KEY_SIZE);

    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt.data(), static_cast<int>(salt.size()),
                          PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key.data()) != 1)
        throw runtime_error("Key derivation failed!");

    return key;
}

EncryptedData AesGcmCipher::encryptWithKey(const string& plaintext, const Bytes& key,
                                           const Bytes& salt, const Bytes& aad) const {
    if (plaintext.empty()) throw invalid_argument("Cannot encrypt empty data!");
    if (plaintext.size() > static_cast<size_t>(numeric_limits<int>::max()))
        throw invalid_argument("Data is too large!");
    if (key.size() != KEY_SIZE || salt.size() != SALT_SIZE)
        throw invalid_argument("Invalid key or salt!");
    if (aad.size() > MAX_AAD_SIZE) throw invalid_argument("Associated data is too large!");

    EncryptedData data;
    data.version = aad.empty() ? FORMAT_LEGACY : FORMAT_BOUND;
    data.salt = salt;
    data.nonce.resize(NONCE_SIZE);
    data.authTag.resize(TAG_SIZE);
    fillRandom(data.nonce);  // fresh nonce for every encryption

    Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) throw runtime_error("Encryption context creation failed!");

    data.ciphertext.resize(plaintext.size() + 16);
    int length = 0, total = 0;

    bool ok =
        EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) == 1 &&
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), data.nonce.data()) == 1 &&
        addAad(context.get(), aad, true) &&
        EVP_EncryptUpdate(context.get(), data.ciphertext.data(), &length,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) == 1;

    if (ok) {
        total = length;
        ok = EVP_EncryptFinal_ex(context.get(), data.ciphertext.data() + total, &length) == 1;
    }

    if (ok) {
        total += length;
        data.ciphertext.resize(total);
        ok = EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                                 data.authTag.data()) == 1;
    }

    if (!ok) throw runtime_error("Encryption failed!");
    return data;
}

string AesGcmCipher::decryptWithKey(const EncryptedData& data, const Bytes& key,
                                    const Bytes& aad) const {
    if (data.version != FORMAT_LEGACY && data.version != FORMAT_BOUND)
        throw invalid_argument("Unsupported encryption format version!");

    // A bound (v2) record must be opened with its binding, and a legacy (v1)
    // record never has one. This also stops a v2 record from being "downgraded".
    if ((data.version == FORMAT_BOUND) == aad.empty())
        throw invalid_argument("Associated data does not match the encryption format!");

    if (aad.size() > MAX_AAD_SIZE) throw invalid_argument("Associated data is too large!");

    if (key.size() != KEY_SIZE || data.salt.size() != SALT_SIZE ||
        data.nonce.size() != NONCE_SIZE || data.authTag.size() != TAG_SIZE ||
        data.ciphertext.empty())
        throw invalid_argument("Invalid encrypted data!");

    if (data.ciphertext.size() > static_cast<size_t>(numeric_limits<int>::max()))
        throw invalid_argument("Encrypted data is too large!");

    Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) throw runtime_error("Decryption context creation failed!");

    Bytes plain(data.ciphertext.size() + 16);
    int length = 0, total = 0;

    bool ok =
        EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) == 1 &&
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), data.nonce.data()) == 1 &&
        addAad(context.get(), aad, false) &&
        EVP_DecryptUpdate(context.get(), plain.data(), &length, data.ciphertext.data(),
                          static_cast<int>(data.ciphertext.size())) == 1;

    if (ok) {
        total = length;
        ok = EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                 const_cast<unsigned char*>(data.authTag.data())) == 1;
    }

    if (ok) ok = EVP_DecryptFinal_ex(context.get(), plain.data() + total, &length) == 1;

    if (!ok) {
        OPENSSL_cleanse(plain.data(), plain.size());
        throw runtime_error("Decryption failed! Wrong master password or corrupted data.");
    }

    total += length;
    string result(reinterpret_cast<const char*>(plain.data()), static_cast<size_t>(total));
    OPENSSL_cleanse(plain.data(), plain.size());
    return result;
}
