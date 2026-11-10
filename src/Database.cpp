
#include "Database.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <limits>
#include <string>
#include <vector>
#include <utility>

using namespace std;

namespace {

using Statement = unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

Statement prepare(sqlite3* db, const string& sql) {
    sqlite3_stmt* rawStatement = nullptr;

    if (sqlite3_prepare_v2(
            db,
            sql.c_str(),
            -1,
            &rawStatement,
            nullptr
        ) != SQLITE_OK) {

        throw runtime_error(
            string("SQLite prepare error: ") + sqlite3_errmsg(db)
        );
    }

    return Statement(rawStatement, sqlite3_finalize);
}

void bindBlob(
    sqlite3_stmt* statement,
    int index,
    const vector<unsigned char>& data,
    sqlite3* db
) {
    if (data.empty() ||
        data.size() > static_cast<size_t>(
            numeric_limits<int>::max()
        )) {
        throw runtime_error("Invalid binary data.");
    }

    if (sqlite3_bind_blob(
            statement,
            index,
            data.data(),
            static_cast<int>(data.size()),
            SQLITE_TRANSIENT
        ) != SQLITE_OK) {

        throw runtime_error(
            string("SQLite bind error: ") + sqlite3_errmsg(db)
        );
    }
}

vector<unsigned char> readBlob(
    sqlite3_stmt* statement,
    int column
) {
    const void* blob = sqlite3_column_blob(statement, column);
    int size = sqlite3_column_bytes(statement, column);

    if (blob == nullptr || size <= 0) {
        throw runtime_error("Invalid or empty encrypted data.");
    }

    const auto* bytes =
        static_cast<const unsigned char*>(blob);

    return vector<unsigned char>(
        bytes,
        bytes + size
    );
}

void bindEncryptedData(
    sqlite3_stmt* statement,
    const EncryptedData& data,
    sqlite3* db
) {
    bindBlob(statement, 1, data.salt, db);
    bindBlob(statement, 2, data.nonce, db);
    bindBlob(statement, 3, data.ciphertext, db);
    bindBlob(statement, 4, data.authTag, db);
}

EncryptedData readEncryptedData(sqlite3_stmt* statement, int offset = 0) {
    EncryptedData data;

    data.salt = readBlob(statement, offset);
    data.nonce = readBlob(statement, offset + 1);
    data.ciphertext = readBlob(statement, offset + 2);
    data.authTag = readBlob(statement, offset + 3);

    return data;
}

} // namespace

// Constructor
Database::Database(const string& databaseName)
    : db(nullptr) {

    if (sqlite3_open(databaseName.c_str(), &db) != SQLITE_OK) {
        string error = db
            ? sqlite3_errmsg(db)
            : "Could not allocate SQLite connection.";

        if (db != nullptr) {
            sqlite3_close(db);
            db = nullptr;
        }

        throw runtime_error("Database connection failed: " + error);
    }

    sqlite3_busy_timeout(db, 5000);
}

// Destructor
Database::~Database() {
    if (db != nullptr) {
        sqlite3_close(db);
        db = nullptr;
    }
}

// Create tables
bool Database::createTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS password_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            auth_tag BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vault_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            auth_tag BLOB NOT NULL
        );
    )";

    char* errorMessage = nullptr;

    int result = sqlite3_exec(
        db,
        sql,
        nullptr,
        nullptr,
        &errorMessage
    );

    if (result != SQLITE_OK) {
        string error = errorMessage
            ? errorMessage
            : sqlite3_errmsg(db);

        sqlite3_free(errorMessage);

        throw runtime_error(
            "Table creation failed: " + error
        );
    }

    return true;
}

// Initialize or verify master password
bool Database::initializeOrVerifyMasterPassword(
    const string& masterPassword
) {
    if (masterPassword.length() < 8) {
        throw invalid_argument(
            "Master password must contain at least 8 characters."
        );
    }

    const string verificationMessage =
        "VAULTX_MASTER_PASSWORD_VERIFIED_2026";

    // Check whether verifier already exists.
    auto statement = prepare(
        db,
        "SELECT salt, nonce, ciphertext, auth_tag "
        "FROM vault_metadata WHERE id = 1;"
    );

    int result = sqlite3_step(statement.get());

    if (result == SQLITE_ROW) {
        EncryptedData data = readEncryptedData(statement.get());

        try {
            string decrypted = Crypto::decrypt(
                data,
                masterPassword
            );

            if (decrypted != verificationMessage) {
                throw runtime_error("Verification failed.");
            }

            return true;
        }
        catch (const exception&) {
            throw runtime_error(
                "Incorrect master password or damaged vault."
            );
        }
    }

    if (result != SQLITE_DONE) {
        throw runtime_error(
            string("SQLite read error: ") + sqlite3_errmsg(db)
        );
    }

    statement.reset();

    // Do not initialize a new password if old records exist.
    statement = prepare(
        db,
        "SELECT COUNT(*) FROM password_entries;"
    );

    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw runtime_error(
            "Could not check existing vault entries."
        );
    }

    int existingEntries =
        sqlite3_column_int(statement.get(), 0);

    statement.reset();

    if (existingEntries > 0) {
        throw runtime_error(
            "Existing vault entries found without a master-password "
            "verifier. Refusing to initialize."
        );
    }

    // First launch: create encrypted verifier.
    EncryptedData data = Crypto::encrypt(
        verificationMessage,
        masterPassword
    );

    statement = prepare(
        db,
        "INSERT INTO vault_metadata "
        "(id, salt, nonce, ciphertext, auth_tag) "
        "VALUES (1, ?, ?, ?, ?);"
    );

    bindEncryptedData(statement.get(), data, db);

    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw runtime_error(
            string("Verifier creation failed: ") +
            sqlite3_errmsg(db)
        );
    }

    return true;
}

// Insert entry
bool Database::insertEntry(const EncryptedData& data) {
    auto statement = prepare(
        db,
        "INSERT INTO password_entries "
        "(salt, nonce, ciphertext, auth_tag) "
        "VALUES (?, ?, ?, ?);"
    );

    bindEncryptedData(statement.get(), data, db);

    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw runtime_error(
            string("Insert failed: ") + sqlite3_errmsg(db)
        );
    }

    return true;
}

// Get all entries
vector<StoredEntry> Database::getAllEntries() const {
    vector<StoredEntry> entries;

    auto statement = prepare(
        db,
        "SELECT id, salt, nonce, ciphertext, auth_tag "
        "FROM password_entries ORDER BY id;"
    );

    while (true) {
        int result = sqlite3_step(statement.get());

        if (result == SQLITE_DONE) {
            break;
        }

        if (result != SQLITE_ROW) {
            throw runtime_error(
                string("Read failed: ") + sqlite3_errmsg(db)
            );
        }

        StoredEntry entry;

        entry.id = sqlite3_column_int(statement.get(), 0);

        entry.encryptedData = readEncryptedData(statement.get(), 1);

        entries.push_back(move(entry));
    }

    return entries;
}

// Update entry
bool Database::updateEntry(
    int id,
    const EncryptedData& data
) {
    if (id <= 0) {
        throw invalid_argument("Invalid entry ID.");
    }

    auto statement = prepare(
        db,
        "UPDATE password_entries "
        "SET salt = ?, nonce = ?, ciphertext = ?, auth_tag = ? "
        "WHERE id = ?;"
    );

    bindEncryptedData(statement.get(), data, db);

    if (sqlite3_bind_int(statement.get(), 5, id) != SQLITE_OK) {
        throw runtime_error(
            string("Could not bind entry ID: ") +
            sqlite3_errmsg(db)
        );
    }

    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw runtime_error(
            string("Update failed: ") + sqlite3_errmsg(db)
        );
    }

    if (sqlite3_changes(db) == 0) {
        throw runtime_error("Entry not found.");
    }

    return true;
}

// Delete entry
bool Database::deleteEntry(int id) {
    if (id <= 0) {
        throw invalid_argument("Invalid entry ID.");
    }

    auto statement = prepare(
        db,
        "DELETE FROM password_entries WHERE id = ?;"
    );

    if (sqlite3_bind_int(statement.get(), 1, id) != SQLITE_OK) {
        throw runtime_error(
            string("Could not bind entry ID: ") +
            sqlite3_errmsg(db)
        );
    }

    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throw runtime_error(
            string("Delete failed: ") + sqlite3_errmsg(db)
        );
    }

    if (sqlite3_changes(db) == 0) {
        throw runtime_error("Entry not found.");
    }

    return true;
}
