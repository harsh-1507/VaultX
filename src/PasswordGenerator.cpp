#include "PasswordGenerator.h"

#include <openssl/rand.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace std;

size_t PasswordGenerator::randomIndex(size_t bound) {
    if (bound == 0) throw invalid_argument("Empty character set.");

    const uint32_t limit = UINT32_MAX - (UINT32_MAX % static_cast<uint32_t>(bound));
    uint32_t value;

    do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1)
            throw runtime_error("Secure random generation failed!");
    } while (value >= limit);

    return value % bound;
}

string PasswordGenerator::generate(const GeneratorOptions& options) {
    if (options.length < 8 || options.length > 128)
        throw invalid_argument("Password length must be between 8 and 128.");

    vector<string> sets;
    if (options.upper) sets.push_back("ABCDEFGHJKLMNPQRSTUVWXYZ");
    if (options.lower) sets.push_back("abcdefghijkmnopqrstuvwxyz");
    if (options.digits) sets.push_back("23456789");
    if (options.symbols) sets.push_back("!@#$%^&*()-_=+[]{}?");

    if (sets.empty()) throw invalid_argument("Select at least one character type.");

    string all, result;
    for (const string& s : sets) {
        all += s;
        result += s[randomIndex(s.size())];  // at least one of every chosen type
    }

    while (result.size() < options.length) result += all[randomIndex(all.size())];

    for (size_t i = result.size() - 1; i > 0; i--)  // Fisher-Yates shuffle
        swap(result[i], result[randomIndex(i + 1)]);

    return result;
}
