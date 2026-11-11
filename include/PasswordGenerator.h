#ifndef PASSWORDGENERATOR_H
#define PASSWORDGENERATOR_H

#include <cstddef>
#include <string>

using namespace std;

struct GeneratorOptions {
    size_t length = 20;
    bool upper = true;
    bool lower = true;
    bool digits = true;
    bool symbols = true;
};

// Cryptographically secure password generator (OpenSSL RAND_bytes).
class PasswordGenerator {
    static size_t randomIndex(size_t bound);  // uniform, no modulo bias

public:
    static std::string generate(const GeneratorOptions& options);
};

#endif
