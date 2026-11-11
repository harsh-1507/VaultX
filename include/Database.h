#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

#include <mutex>
#include <string>

#include "Storage.h"

using namespace std;

// SQLite implementation of Storage.
//
// Thread safety: every public method takes an internal mutex, so one Database
// object may be shared between threads (multi-statement operations such as
// insertSealed() and replaceVault() are therefore never interleaved).
// Several processes may open the same file; SQLite's file locking plus the
// 5 second busy timeout arbitrates between them.
class Database : public Storage {
    sqlite3* db = nullptr;
    string path_;
    mutable mutex mutex_;

    bool columnExists(const string& table, const string& column) const;

public:
    explicit Database(const string& databaseName);
    ~Database() override;

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    const string& path() const { return path_; }

    void createTables() override;

    bool hasVerifier() const override;
    optional<EncryptedData> loadVerifier() const override;
    void saveVerifier(const EncryptedData& verifier) override;

    size_t entryCount() const override;
    bool insertEntry(const EncryptedData& data) override;
    long long lastInsertId() const override;
    vector<StoredEntry> getAllEntries() const override;
    bool updateEntry(int id, const EncryptedData& data) override;
    bool deleteEntry(int id) override;

    long long insertSealed(const function<EncryptedData(long long)>& seal) override;
    bool replaceEntries(const vector<pair<int, EncryptedData>>& rows) override;
    bool replaceVault(const vector<pair<int, EncryptedData>>& rows,
                      const EncryptedData& verifier) override;

    string createBackup(const string& label) override;
};

#endif
