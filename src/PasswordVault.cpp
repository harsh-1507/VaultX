
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <string>

#include "PasswordVault.h"

using namespace std;

// Convert service name to lowercase
string normalizeService(string service) {

    transform(service.begin(), service.end(),
              service.begin(),
              [](unsigned char ch) {
                  return static_cast<char>(tolower(ch));
              });

    return service;
}

// Add account with duplicate detection
bool PasswordVault::addEntry(const PasswordEntry& entry) {

    for (const PasswordEntry& existing : entries) {

        if (normalizeService(existing.getService()) ==
            normalizeService(entry.getService())) {

            cout << "\n[ERROR] This service already exists!\n";
            return false;
        }
    }

    entries.push_back(entry);

    cout << "\n[SUCCESS] Account added successfully!\n";
    return true;
}

// Display all accounts
void PasswordVault::displayAll() const {

    if (entries.empty()) {
        cout << "\nYour vault is currently empty!\n";
        return;
    }

    cout << "\n";
    cout << left
         << setw(20) << "SERVICE"
         << setw(25) << "USERNAME"
         << setw(20) << "CATEGORY" << endl;

    cout << string(65, '-') << endl;

    for (const PasswordEntry& entry : entries) {

        cout << left
             << setw(20) << entry.getService()
             << setw(25) << entry.getUsername()
             << setw(20) << entry.getCategory()
             << endl;
    }

    cout << string(65, '-') << endl;
    cout << "Total accounts: " << entries.size() << endl;
}

// Search account
void PasswordVault::searchByService(const string& service) const {

    string target = normalizeService(service);

    for (const PasswordEntry& entry : entries) {

        if (normalizeService(entry.getService()) == target) {

            cout << "\n========== ACCOUNT FOUND ==========\n";
            cout << "Service  : " << entry.getService() << endl;
            cout << "Username : " << entry.getUsername() << endl;
            cout << "Category : " << entry.getCategory() << endl;

            return;
        }
    }

    cout << "\n[ERROR] Account not found!\n";
}

// Delete account
void PasswordVault::deleteEntry(const string& service) {

    string target = normalizeService(service);

    auto oldSize = entries.size();

    entries.erase(
        remove_if(
            entries.begin(),
            entries.end(),
            [&target](const PasswordEntry& entry) {
                return normalizeService(entry.getService()) == target;
            }
        ),
        entries.end()
    );

    if (entries.size() < oldSize) {
        cout << "\n[SUCCESS] Account deleted!\n";
    }
    else {
        cout << "\n[ERROR] Account not found!\n";
    }
}

// Edit existing account
void PasswordVault::editEntry(const string& service,
                              const string& newUsername,
                              const string& newPassword,
                              const string& newCategory) {

    string target = normalizeService(service);

    for (PasswordEntry& entry : entries) {

        if (normalizeService(entry.getService()) == target) {

            // Validate all new values before modifying the object
            if (newUsername.empty()) {
                throw invalid_argument("Username cannot be empty!");
            }

            if (newPassword.length() < 6) {
                throw invalid_argument(
                    "Password must contain at least 6 characters!"
                );
            }

            if (newCategory.empty()) {
                throw invalid_argument("Category cannot be empty!");
            }

            entry.setUsername(newUsername);
            entry.setPassword(newPassword);
            entry.setCategory(newCategory);

            cout << "\n[SUCCESS] Account updated successfully!\n";
            return;
        }
    }

    cout << "\n[ERROR] Account not found!\n";
}
