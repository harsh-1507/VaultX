
#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <string>
#include <vector>

#include "Crypto.h"

using namespace std;

struct StoredEntry {
    int id;
    EncryptedData encryptedData;
};

class Database {
private:
    sqlite3* db;

public:
    Database(const string& databaseName);
    ~Database();

    bool createTables();

    bool insertEntry(const EncryptedData& data);

    vector<StoredEntry> getAllEntries() const;

    bool updateEntry(
        int id,
        const EncryptedData& data
    );
    bool initializeOrVerifyMasterPassword(const string& masterPassword);
    bool deleteEntry(int id);
    bool hasMasterPassword() const;
    long long lastInsertId() const;
};

#endif
