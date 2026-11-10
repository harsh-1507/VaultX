#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>

using namespace std;

struct EncryptedData {
    vector<unsigned char> salt;
    vector<unsigned char> nonce;
    vector<unsigned char> ciphertext;
    vector<unsigned char> authTag;
};

class Crypto {
public:
    static EncryptedData encrypt(
        const string& plaintext,
        const string& masterPassword
    );

    static string decrypt(
        const EncryptedData& data,
        const string& masterPassword
    );
};

#endif
