// Crypto layer tests: AES-256-GCM, AAD binding, tampering, randomness and
// compatibility with records written by the ORIGINAL (pre-AAD) code.
// Uses the real AesGcmCipher (600,000 PBKDF2 rounds), so key derivations are
// kept to a minimum here.

#include <set>

#include "Crypto.h"
#include "TestFramework.h"

using namespace std;

namespace {

Bytes fromHex(const string& hex) {
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<unsigned char>(stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

Bytes text(const string& s) { return Bytes(s.begin(), s.end()); }

const string PLAINTEXT = "{\"title\":\"Example\",\"password\":\"hunter2-hunter2\"}";

// One real (slow) key per test run is enough for everything that needs "a key".
const Bytes& sharedKey(const AesGcmCipher& cipher, Bytes& saltOut) {
    static Bytes salt = cipher.randomSalt();
    static Bytes key = cipher.deriveKey("shared-test-password", salt);
    saltOut = salt;
    return key;
}

}  // namespace

TEST_CASE(roundtrip_with_password) {
    AesGcmCipher cipher;
    EncryptedData data = cipher.encrypt(PLAINTEXT, "master-password-1");

    CHECK_EQ(data.version, FORMAT_LEGACY);  // no AAD -> legacy format number
    CHECK_EQ(data.salt.size(), 16u);
    CHECK_EQ(data.nonce.size(), 12u);
    CHECK_EQ(data.authTag.size(), 16u);
    CHECK_EQ(data.ciphertext.size(), PLAINTEXT.size());  // GCM is length-preserving
    CHECK_EQ(cipher.decrypt(data, "master-password-1"), PLAINTEXT);
}

TEST_CASE(roundtrip_with_key_and_aad) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);

    EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt, text("record/7"));
    CHECK_EQ(data.version, FORMAT_BOUND);
    CHECK_EQ(cipher.decryptWithKey(data, key, text("record/7")), PLAINTEXT);
}

TEST_CASE(wrong_key_or_password_fails) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);
    EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt);

    Bytes wrong = key;
    wrong[0] ^= 0x01;
    CHECK_THROWS_AS(cipher.decryptWithKey(data, wrong), runtime_error);
    CHECK_THROWS_AS(cipher.decrypt(data, "not-the-password"), runtime_error);
}

TEST_CASE(modified_ciphertext_fails) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);
    EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt);

    for (size_t position : {size_t(0), data.ciphertext.size() / 2, data.ciphertext.size() - 1}) {
        EncryptedData bad = data;
        bad.ciphertext[position] ^= 0x80;
        CHECK_THROWS_AS(cipher.decryptWithKey(bad, key), runtime_error);
    }

    EncryptedData truncated = data;
    truncated.ciphertext.pop_back();
    CHECK_THROWS_AS(cipher.decryptWithKey(truncated, key), runtime_error);
}

TEST_CASE(modified_authentication_tag_fails) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);
    EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt);

    for (size_t position = 0; position < data.authTag.size(); position++) {
        EncryptedData bad = data;
        bad.authTag[position] ^= 0x01;
        CHECK_THROWS_AS(cipher.decryptWithKey(bad, key), runtime_error);
    }

    EncryptedData shortTag = data;
    shortTag.authTag.pop_back();
    CHECK_THROWS_AS(cipher.decryptWithKey(shortTag, key), invalid_argument);
}

TEST_CASE(modified_nonce_fails) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);
    EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt);

    for (size_t position = 0; position < data.nonce.size(); position++) {
        EncryptedData bad = data;
        bad.nonce[position] ^= 0x01;
        CHECK_THROWS_AS(cipher.decryptWithKey(bad, key), runtime_error);
    }
}

TEST_CASE(aad_mismatch_fails) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);
    EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt, text("record/1"));

    // Another record id (this is what "moving ciphertext between records" looks like).
    CHECK_THROWS_AS(cipher.decryptWithKey(data, key, text("record/2")), runtime_error);
    CHECK_THROWS_AS(cipher.decryptWithKey(data, key, text("record/1 ")), runtime_error);

    // A bound record cannot be opened without its binding...
    CHECK_THROWS_AS(cipher.decryptWithKey(data, key), invalid_argument);

    // ...and relabelling it as a legacy record does not bypass the check:
    // the tag was computed over the AAD, so authentication still fails.
    EncryptedData downgraded = data;
    downgraded.version = FORMAT_LEGACY;
    CHECK_THROWS_AS(cipher.decryptWithKey(downgraded, key), runtime_error);

    // A legacy record never accepts AAD.
    EncryptedData legacy = cipher.encryptWithKey(PLAINTEXT, key, salt);
    CHECK_THROWS_AS(cipher.decryptWithKey(legacy, key, text("record/1")), invalid_argument);
}

TEST_CASE(salt_and_nonce_are_random_and_unique) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);

    set<Bytes> salts, nonces, ciphertexts;
    for (int i = 0; i < 200; i++) {
        salts.insert(cipher.randomSalt());
        EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt);  // same input every time
        nonces.insert(data.nonce);
        ciphertexts.insert(data.ciphertext);
    }

    CHECK_EQ(salts.size(), 200u);
    CHECK_EQ(nonces.size(), 200u);        // a fresh nonce for every encryption
    CHECK_EQ(ciphertexts.size(), 200u);   // so identical plaintext never repeats
    CHECK(cipher.randomSalt().size() == 16);
}

TEST_CASE(key_derivation_is_deterministic_and_salted) {
    AesGcmCipher cipher;
    Bytes salt1 = cipher.randomSalt(), salt2 = cipher.randomSalt();

    Bytes a = cipher.deriveKey("same-password", salt1);
    Bytes b = cipher.deriveKey("same-password", salt1);
    Bytes c = cipher.deriveKey("same-password", salt2);

    CHECK_EQ(a.size(), 32u);
    CHECK(a == b);
    CHECK(a != c);
}

TEST_CASE(invalid_inputs_are_rejected) {
    AesGcmCipher cipher;
    Bytes salt, key = sharedKey(cipher, salt);

    CHECK_THROWS_AS(cipher.encryptWithKey("", key, salt), invalid_argument);
    CHECK_THROWS_AS(cipher.deriveKey("", salt), invalid_argument);
    CHECK_THROWS_AS(cipher.deriveKey("pw", Bytes(5)), invalid_argument);
    CHECK_THROWS_AS(cipher.encryptWithKey("x", Bytes(5), salt), invalid_argument);

    EncryptedData data = cipher.encryptWithKey(PLAINTEXT, key, salt);
    EncryptedData future = data;
    future.version = 3;
    CHECK_THROWS_AS(cipher.decryptWithKey(future, key), invalid_argument);
}

TEST_CASE(reads_record_written_by_the_original_code) {
    // Produced by the ORIGINAL Crypto.cpp from the uploaded project (before AAD
    // existed): proves old databases stay readable after the upgrade.
    EncryptedData legacy;
    legacy.version = FORMAT_LEGACY;
    legacy.salt = fromHex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    legacy.nonce = fromHex("54869381cf5f39accdf3d9ee");
    legacy.ciphertext = fromHex(
        "675bba022ce72cc37f506a5fc0f8118c313bbbf6641a38d085f7c651c67216ae1ba846ba006e9eab2f04aa4f"
        "f2d123e5c6e0a95a379460efcf3b0f7d52b46068215b2a0e71389b18e6bfea8ec17aa20d7a4af5aa7f5e6335"
        "138bdcd59f81ddb1a669845ccefc7f0c8f1d32e7f20e4b9e23195fb89448450a4ccf410ee8f77c40d37d8a59"
        "972754f014956666a3954131b53f93eb5f44f728448711bdd523c4ef4392eeff5305cf9ae02c2bdcca3c8993"
        "4a78c9c1528dc3b08284ee79ace6a6bfc4");
    legacy.authTag = fromHex("eb07a2e277e59a64362e47f6d138e98b");

    AesGcmCipher cipher;
    string plain = cipher.decrypt(legacy, "legacy-Master#Pass-2024");

    CHECK(plain.find("\"title\":\"Legacy Site\"") != string::npos);
    CHECK(plain.find("Sup3r-Secret!") != string::npos);
    CHECK_THROWS(cipher.decrypt(legacy, "wrong-password"));
}

TEST_CASE(secure_buffers_are_wiped_in_place) {
    Bytes secret(32, 0xAB);
    const unsigned char* raw = secret.data();  // the buffer stays allocated after wipe()

    wipe(secret);
    CHECK(secret.empty());
    for (int i = 0; i < 32; i++) CHECK_EQ(static_cast<int>(raw[i]), 0);

    string password = "hunter2-hunter2";
    {
        StringWiper guard(password);
    }
    CHECK(password.empty());
}
