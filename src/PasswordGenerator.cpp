#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <bcrypt.h>

#include "PasswordGenerator.h"

#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <string>
#include <utility>

using namespace std;
// Generate a secure random 32-bit number
uint32_t secureRandomNumber() {

    uint32_t number = 0;

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(&number),
        sizeof(number),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status != 0) {
        throw runtime_error("Secure random number generation failed!");
    }

    return number;
}

// Generate an unbiased random index
uint32_t secureRandomIndex(uint32_t upperLimit) {

    if (upperLimit == 0) {
        throw invalid_argument("Invalid random range!");
    }

    uint32_t threshold = (0u - upperLimit) % upperLimit;

    while (true) {

        uint32_t number = secureRandomNumber();

        if (number >= threshold) {
            return number % upperLimit;
        }
    }
}

// Select a random character from a character set
char randomCharacter(const string& characters) {

    uint32_t index = secureRandomIndex(
        static_cast<uint32_t>(characters.size())
    );

    return characters[index];
}

// Generate password
string PasswordGenerator::generatePassword(
    int length,
    bool uppercase,
    bool lowercase,
    bool numbers,
    bool specialCharacters
) {

    if (length < 8 || length > 128) {
        throw invalid_argument(
            "Password length must be between 8 and 128!"
        );
    }

    string upperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string lowerSet = "abcdefghijklmnopqrstuvwxyz";
    string numberSet = "0123456789";
    string specialSet = "!@#$%^&*()-_=+[]{}?";

    vector<string> selectedSets;
    string allCharacters;

    if (uppercase) {
        selectedSets.push_back(upperSet);
        allCharacters += upperSet;
    }

    if (lowercase) {
        selectedSets.push_back(lowerSet);
        allCharacters += lowerSet;
    }

    if (numbers) {
        selectedSets.push_back(numberSet);
        allCharacters += numberSet;
    }

    if (specialCharacters) {
        selectedSets.push_back(specialSet);
        allCharacters += specialSet;
    }

    if (selectedSets.empty()) {
        throw invalid_argument(
            "Select at least one character category!"
        );
    }

    if (length < static_cast<int>(selectedSets.size())) {
        throw invalid_argument(
            "Password length is too small for selected categories!"
        );
    }

    string password;

    // Guarantee at least one character from each selected category
    for (const string& characterSet : selectedSets) {
        password += randomCharacter(characterSet);
    }

    // Fill the remaining positions
    while (static_cast<int>(password.length()) < length) {
        password += randomCharacter(allCharacters);
    }

    // Securely shuffle the generated password
    for (int i = static_cast<int>(password.size()) - 1; i > 0; i--) {

        uint32_t j = secureRandomIndex(
            static_cast<uint32_t>(i + 1)
        );

        swap(password[i], password[j]);
    }

    return password;
}
