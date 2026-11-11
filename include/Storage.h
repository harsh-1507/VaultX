#ifndef STORAGE_H
#define STORAGE_H

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "Crypto.h"

using namespace std;

struct StoredEntry {
    int id = 0;
    EncryptedData encryptedData;
};

// Abstract persistence layer. The vault only knows this interface, so SQLite
// could be swapped for another database by writing a new derived class.
class Storage {
public:
    virtual ~Storage() = default;

    virtual void createTables() = 0;

    // master-password verifier
    virtual bool hasVerifier() const = 0;
    virtual optional<EncryptedData> loadVerifier() const = 0;
    virtual void saveVerifier(const EncryptedData& verifier) = 0;

    // records (always stored encrypted)
    virtual size_t entryCount() const = 0;
    virtual bool insertEntry(const EncryptedData& data) = 0;
    virtual long long lastInsertId() const = 0;
    virtual vector<StoredEntry> getAllEntries() const = 0;
    virtual bool updateEntry(int id, const EncryptedData& data) = 0;
    virtual bool deleteEntry(int id) = 0;

    // Inserts a record whose encryption needs its own id (AAD binding).
    // The id is reserved inside a transaction, `seal(id)` produces the final
    // encrypted data, and the row is completed and committed. If seal() or any
    // step throws, nothing is stored. seal() must NOT call back into Storage.
    virtual long long insertSealed(const function<EncryptedData(long long)>& seal) = 0;

    // Replaces the listed records in one all-or-nothing step.
    virtual bool replaceEntries(const vector<pair<int, EncryptedData>>& rows) = 0;

    // Replaces every record and the verifier in one all-or-nothing step.
    virtual bool replaceVault(const vector<pair<int, EncryptedData>>& rows,
                              const EncryptedData& verifier) = 0;

    // Writes a consistent copy of the whole store next to the original and
    // returns where it was written. Used before any data-format migration.
    virtual string createBackup(const string& label) = 0;
};

#endif
