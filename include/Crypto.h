#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>

#include "SecureMemory.h"  // defines Bytes (a self-wiping byte vector)

using namespace std;

// Encryption format versions stored next to every record.
//   1 = original format: AES-256-GCM, no additional authenticated data.
//   2 = record-bound format: the database record id is authenticated as AAD,
//       so a ciphertext cannot be moved to another record without detection.
constexpr int FORMAT_LEGACY = 1;
constexpr int FORMAT_BOUND = 2;

struct EncryptedData {
    Bytes salt;
    Bytes nonce;
    Bytes ciphertext;
    Bytes authTag;
    int version = FORMAT_LEGACY;
};

// Abstract cipher.
// Derived classes supply the primitives; the base class builds the
// password-based operations on top of them (Template Method pattern).
//
// `aad` is "additional authenticated data": it is not encrypted, but the
// authentication tag only verifies if the same bytes are supplied again.
// Empty aad = format version 1, non-empty aad = format version 2.
class Cipher {
public:
    virtual ~Cipher() = default;

    virtual Bytes randomSalt() const = 0;
    virtual Bytes deriveKey(const string& password, const Bytes& salt) const = 0;
    virtual EncryptedData encryptWithKey(const string& plaintext, const Bytes& key,
                                         const Bytes& salt,
                                         const Bytes& aad = Bytes()) const = 0;
    virtual string decryptWithKey(const EncryptedData& data, const Bytes& key,
                                  const Bytes& aad = Bytes()) const = 0;

    // Convenience: derive a key from the password, then encrypt/decrypt.
    EncryptedData encrypt(const string& plaintext, const string& password,
                          const Bytes& aad = Bytes()) const;
    string decrypt(const EncryptedData& data, const string& password,
                   const Bytes& aad = Bytes()) const;
};

// AES-256-GCM with PBKDF2-HMAC-SHA256 (600,000 iterations).
class AesGcmCipher : public Cipher {
public:
    Bytes randomSalt() const override;
    Bytes deriveKey(const string& password, const Bytes& salt) const override;
    EncryptedData encryptWithKey(const string& plaintext, const Bytes& key,
                                 const Bytes& salt,
                                 const Bytes& aad = Bytes()) const override;
    string decryptWithKey(const EncryptedData& data, const Bytes& key,
                          const Bytes& aad = Bytes()) const override;
};

#endif
