
#include "PasswordVault.h"
#include "Crypto.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <stdexcept>

using namespace std;

namespace {
    string normalizeService(string service) {
        transform(
            service.begin(),
            service.end(),
            service.begin(),
            [](unsigned char ch) {
                return static_cast<char>(tolower(ch));
            }
        );

        return service;
    }
}

PasswordVault::PasswordVault(
    Database& database,
    const string& masterPassword
) : database(database), masterPassword(masterPassword) {
    if (masterPassword.empty()) {
        throw invalid_argument("Master password cannot be empty!");
    }
}

string PasswordVault::serializeEntry(
    const PasswordEntry& entry
) const {
    ostringstream output;

    output << quoted(entry.getService()) << ' '
           << quoted(entry.getUsername()) << ' '
           << quoted(entry.getPassword()) << ' '
           << quoted(entry.getCategory());

    return output.str();
}

PasswordEntry PasswordVault::deserializeEntry(
    const string& data
) const {
    istringstream input(data);

    string service;
    string username;
    string password;
    string category;

    if (!(input >> quoted(service)
                >> quoted(username)
                >> quoted(password)
                >> quoted(category))) {
        throw runtime_error("Invalid decrypted account data!");
    }

    input >> ws;

    if (!input.eof()) {
        throw runtime_error("Unexpected data in decrypted account!");
    }

    return PasswordEntry(
        service,
        username,
        password,
        category
    );
}

bool PasswordVault::addEntry(const PasswordEntry& entry) {
    try {
        vector<StoredEntry> existing = database.getAllEntries();

        for (const StoredEntry& stored : existing) {
            string plaintext = Crypto::decrypt(
                stored.encryptedData,
                masterPassword
            );

            PasswordEntry current = deserializeEntry(plaintext);

            if (normalizeService(current.getService()) ==
                normalizeService(entry.getService())) {
                cout << "[ERROR] Service already exists!\n";
                return false;
            }
        }

        string plaintext = serializeEntry(entry);

        EncryptedData encrypted = Crypto::encrypt(
            plaintext,
            masterPassword
        );

        return database.insertEntry(encrypted);
    }
    catch (const exception& e) {
        cerr << "[VAULT ERROR] " << e.what() << endl;
        return false;
    }
}

void PasswordVault::displayAll() const {
    try {
        vector<StoredEntry> entries = database.getAllEntries();

        if (entries.empty()) {
            cout << "\nVault is empty!\n";
            return;
        }

        cout << "\n========== YOUR VAULT ==========\n";

        for (const StoredEntry& stored : entries) {
            string plaintext = Crypto::decrypt(
                stored.encryptedData,
                masterPassword
            );

            PasswordEntry entry = deserializeEntry(plaintext);

            cout << "\nID       : " << stored.id << endl;
            cout << "Service  : " << entry.getService() << endl;
            cout << "Username : " << entry.getUsername() << endl;
            cout << "Category : " << entry.getCategory() << endl;

            // Never display passwords in the account list.
        }

        cout << "\n================================\n";
    }
    catch (const exception& e) {
        cerr << "[VAULT ERROR] " << e.what() << endl;
    }
}

void PasswordVault::searchByService(
    const string& service
) const {
    try {
        vector<StoredEntry> entries = database.getAllEntries();

        for (const StoredEntry& stored : entries) {
            string plaintext = Crypto::decrypt(
                stored.encryptedData,
                masterPassword
            );

            PasswordEntry entry = deserializeEntry(plaintext);

            if (normalizeService(entry.getService()) ==
                normalizeService(service)) {

                cout << "\n========== ACCOUNT FOUND ==========\n";
                cout << "ID       : " << stored.id << endl;
                cout << "Service  : " << entry.getService() << endl;
                cout << "Username : " << entry.getUsername() << endl;
                cout << "Category : " << entry.getCategory() << endl;

                return;
            }
        }

        cout << "[ERROR] Account not found!\n";
    }
    catch (const exception& e) {
        cerr << "[VAULT ERROR] " << e.what() << endl;
    }
}

bool PasswordVault::deleteEntry(int id) {
    return database.deleteEntry(id);
}

bool PasswordVault::editEntry(
    int id,
    const string& newUsername,
    const string& newPassword,
    const string& newCategory
) {
    try {
        if (newUsername.empty() ||
            newPassword.length() < 6 ||
            newCategory.empty()) {
            throw invalid_argument("Invalid account details!");
        }

        vector<StoredEntry> entries = database.getAllEntries();

        for (const StoredEntry& stored : entries) {
            if (stored.id != id) {
                continue;
            }

            string plaintext = Crypto::decrypt(
                stored.encryptedData,
                masterPassword
            );

            PasswordEntry oldEntry = deserializeEntry(plaintext);

            PasswordEntry updatedEntry(
                oldEntry.getService(),
                newUsername,
                newPassword,
                newCategory
            );

            EncryptedData encrypted = Crypto::encrypt(
                serializeEntry(updatedEntry),
                masterPassword
            );

            return database.updateEntry(id, encrypted);
        }

        cout << "[ERROR] Account not found!\n";
        return false;
    }
    catch (const exception& e) {
        cerr << "[VAULT ERROR] " << e.what() << endl;
        return false;
    }
}
