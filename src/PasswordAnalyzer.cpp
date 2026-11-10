
#include "PasswordAnalyzer.h"

#include <cctype>
#include <algorithm>

using namespace std;

// Check whether a password contains a common weak password
bool isCommonPassword(const string& password) {

    vector<string> commonPasswords = {
        "password",
        "password123",
        "123456",
        "12345678",
        "qwerty",
        "admin",
        "letmein",
        "welcome"
    };

    string lowerPassword = password;

    transform(
        lowerPassword.begin(),
        lowerPassword.end(),
        lowerPassword.begin(),
        [](unsigned char ch) {
            return static_cast<char>(tolower(ch));
        }
    );

    return find(
        commonPasswords.begin(),
        commonPasswords.end(),
        lowerPassword
    ) != commonPasswords.end();
}

// Detect simple ascending sequences
bool hasSimpleSequence(const string& password) {

    int sequenceLength = 1;

    for (size_t i = 1; i < password.length(); i++) {

        if (static_cast<unsigned char>(password[i]) ==
            static_cast<unsigned char>(password[i - 1]) + 1) {

            sequenceLength++;

            if (sequenceLength >= 4) {
                return true;
            }
        }
        else {
            sequenceLength = 1;
        }
    }

    return false;
}

// Main analysis function
PasswordAnalysis PasswordAnalyzer::analyze(
    const string& password
) {

    PasswordAnalysis result;

    result.score = 0;

    if (password.empty()) {
        result.strength = "Very Weak";
        result.suggestions.push_back(
            "Password cannot be empty."
        );
        return result;
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;
    bool hasRepeatedCharacter = false;

    for (unsigned char ch : password) {

        if (isupper(ch)) {
            hasUpper = true;
        }
        else if (islower(ch)) {
            hasLower = true;
        }
        else if (isdigit(ch)) {
            hasDigit = true;
        }
        else {
            hasSpecial = true;
        }
    }

    // Detect consecutive repeated characters
    for (size_t i = 1; i < password.length(); i++) {

        if (password[i] == password[i - 1]) {
            hasRepeatedCharacter = true;
            break;
        }
    }

    // Length score
    if (password.length() >= 16) {
        result.score += 40;
    }
    else if (password.length() >= 12) {
        result.score += 30;
    }
    else if (password.length() >= 8) {
        result.score += 20;
    }
    else if (password.length() >= 6) {
        result.score += 10;
    }
    else {
        result.suggestions.push_back(
            "Use at least 8 characters; longer is better."
        );
    }

    // Character variety
    if (hasUpper) result.score += 10;
    else result.suggestions.push_back(
        "Add uppercase letters."
    );

    if (hasLower) result.score += 10;
    else result.suggestions.push_back(
        "Add lowercase letters."
    );

    if (hasDigit) result.score += 10;
    else result.suggestions.push_back(
        "Add numbers."
    );

    if (hasSpecial) result.score += 10;
    else result.suggestions.push_back(
        "Add special characters."
    );

    // Weak pattern checks
    if (hasRepeatedCharacter) {
        result.score -= 10;

        result.suggestions.push_back(
            "Avoid consecutive repeated characters."
        );
    }

    if (hasSimpleSequence(password)) {
        result.score -= 15;

        result.suggestions.push_back(
            "Avoid simple ascending sequences."
        );
    }

    if (isCommonPassword(password)) {
        result.score = 0;

        result.suggestions.push_back(
            "This is a commonly used password. Choose a unique one."
        );
    }

    // Keep score within 0-100
    result.score = max(0, min(100, result.score));

    // Strength category
    if (result.score < 30) {
        result.strength = "Very Weak";
    }
    else if (result.score < 50) {
        result.strength = "Weak";
    }
    else if (result.score < 70) {
        result.strength = "Medium";
    }
    else if (result.score < 90) {
        result.strength = "Strong";
    }
    else {
        result.strength = "Very Strong";
    }

    return result;
}
