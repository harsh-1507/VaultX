
#include "PasswordEntry.h"

#include <cctype>
#include <stdexcept>

using namespace std;

bool isValidService(const string& service) {

    if (service.empty()) {
        return false;
    }

    for (unsigned char ch : service) {
        if (!isalnum(ch) &&
            ch != ' ' &&
            ch != '.' &&
            ch != '-' &&
            ch != '_') {
            return false;
        }
    }

    return true;
}

PasswordEntry::PasswordEntry(string service,
                             string username,
                             string password,
                             string category)
    : service(service),
      username(username),
      password(password),
      category(category) {

    if (!isValidService(service)) {
        throw invalid_argument("Invalid service name!");
    }

    if (username.empty()) {
        throw invalid_argument("Username cannot be empty!");
    }

    if (password.length() < 6) {
        throw invalid_argument("Password must contain at least 6 characters!");
    }

    if (category.empty()) {
        throw invalid_argument("Category cannot be empty!");
    }
}

// Getters
string PasswordEntry::getService() const {
    return service;
}

string PasswordEntry::getUsername() const {
    return username;
}

string PasswordEntry::getPassword() const {
    return password;
}

string PasswordEntry::getCategory() const {
    return category;
}

// Setters
void PasswordEntry::setUsername(string newUsername) {

    if (newUsername.empty()) {
        throw invalid_argument("Username cannot be empty!");
    }

    username = newUsername;
}

void PasswordEntry::setPassword(string newPassword) {

    if (newPassword.length() < 6) {
        throw invalid_argument("Password must contain at least 6 characters!");
    }

    password = newPassword;
}

void PasswordEntry::setCategory(string newCategory) {

    if (newCategory.empty()) {
        throw invalid_argument("Category cannot be empty!");
    }

    category = newCategory;
}
