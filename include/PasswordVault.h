
#ifndef PASSWORDVAULT_H
#define PASSWORDVAULT_H

#include <vector>
#include "PasswordEntry.h"

using namespace std;

class PasswordVault {
private:
    vector<PasswordEntry> entries;

public:
    bool addEntry(const PasswordEntry& entry);

    void displayAll() const;

    void searchByService(const string& service) const;

    void deleteEntry(const string& service);

    void editEntry(const string& service,
                   const string& newUsername,
                   const string& newPassword,
                   const string& newCategory);
};

#endif
