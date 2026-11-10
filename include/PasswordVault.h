
#ifndef PASSWORDVAULT_H
#define PASSWORDVAULT_H

#include "Database.h"
#include "PasswordEntry.h"

#include <string>

using namespace std;

class PasswordVault {
private:
    Database& database;
    string masterPassword;

    string serializeEntry(const PasswordEntry& entry) const;
    PasswordEntry deserializeEntry(const string& data) const;

public:
    PasswordVault(Database& database, const string& masterPassword);

    bool addEntry(const PasswordEntry& entry);
    void displayAll() const;
    void searchByService(const string& service) const;

    bool deleteEntry(int id);

    bool editEntry(
        int id,
        const string& newUsername,
        const string& newPassword,
        const string& newCategory
    );
};

#endif
