#ifndef TESTSUPPORT_H
#define TESTSUPPORT_H

// Helpers shared by the vault / API tests.

#include <openssl/evp.h>
#include <sqlite3.h>

#include <atomic>
#include <string>

#include <functional>

#include "Crypto.h"
#include "Errors.h"
#include "TestFramework.h"

using namespace std;

// The production cipher derives keys with 600,000 PBKDF2 rounds (~0.2 s each),
// which would make hundreds of unlock/re-encrypt operations take minutes.
// This test-only subclass keeps AES-256-GCM, AAD handling and everything else
// from AesGcmCipher but derives keys with 1,000 rounds. (PasswordVault only
// sees the Cipher interface, which is exactly what makes this swap possible.)
// test_crypto.cpp and one vault test use the real AesGcmCipher.
class FastCipher : public AesGcmCipher {
public:
    Bytes deriveKey(const string& password, const Bytes& salt) const override {
        if (password.empty() || salt.size() != 16)
            throw invalid_argument("Invalid master password or salt!");

        Bytes key(32);
        if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                              salt.data(), static_cast<int>(salt.size()), 1000, EVP_sha256(),
                              32, key.data()) != 1)
            throw runtime_error("Key derivation failed!");
        return key;
    }
};

// Fails the Nth encryption (counting from 1) to simulate a mid-operation error.
class FailingCipher : public FastCipher {
public:
    mutable atomic<int> calls{0};
    int failOnCall = 0;  // 0 = never fail

    EncryptedData encryptWithKey(const string& plaintext, const Bytes& key, const Bytes& salt,
                                 const Bytes& aad = Bytes()) const override {
        if (failOnCall > 0 && ++calls == failOnCall)
            throw runtime_error("simulated encryption failure");
        return FastCipher::encryptWithKey(plaintext, key, salt, aad);
    }
};

// Runs raw SQL on a SEPARATE connection, the way another program (or an
// attacker with write access to the file) would.
inline void rawSql(const string& path, const string& sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) !=
        SQLITE_OK)
        throw runtime_error("rawSql open failed");
    sqlite3_busy_timeout(db, 5000);

    char* err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    string message = err ? err : "";
    sqlite3_free(err);
    sqlite3_close_v2(db);

    if (rc != SQLITE_OK) throw runtime_error("rawSql failed: " + message);
}

// HTTP-style status of the ApiError thrown by fn: 0 = nothing thrown,
// -1 = something other than ApiError was thrown.
inline int errorCode(const function<void()>& fn) {
    try { fn(); }
    catch (const ApiError& e) { return e.code(); }
    catch (...) { return -1; }
    return 0;
}

// A password that passes the master-password strength rules.
inline const string& strongPassword() {
    static const string password = "Correct-Horse-Battery-9!";
    return password;
}

inline const string& otherStrongPassword() {
    static const string password = "Another-Strong-Passphrase-42#";
    return password;
}

#endif
