#include "Database.h"

#include <cctype>
#include <chrono>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>

using namespace std;

namespace {

constexpr size_t MAX_SMALL_BLOB = 64;               // salt, nonce, tag
constexpr size_t MAX_CIPHERTEXT = 4 * 1024 * 1024;  // one record, far above any real entry

using Statement = unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

string lastError(sqlite3* db) {
    return db ? string(sqlite3_errmsg(db)) : string("no database connection");
}

void execute(sqlite3* db, const char* sql, const string& what) {
    char* errorText = nullptr;

    if (sqlite3_exec(db, sql, nullptr, nullptr, &errorText) != SQLITE_OK) {
        string message = errorText ? errorText : lastError(db);
        sqlite3_free(errorText);
        throw runtime_error(what + ": " + message);
    }
}

Statement prepare(sqlite3* db, const string& sql) {
    sqlite3_stmt* raw = nullptr;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr) != SQLITE_OK)
        throw runtime_error("SQLite prepare error: " + lastError(db));

    return Statement(raw, sqlite3_finalize);
}

void bindInt(sqlite3_stmt* statement, int index, int value, sqlite3* db) {
    if (sqlite3_bind_int(statement, index, value) != SQLITE_OK)
        throw runtime_error("SQLite bind error: " + lastError(db));
}

void bindBlob(sqlite3_stmt* statement, int index, const Bytes& data, size_t maxSize,
              sqlite3* db) {
    if (data.empty() || data.size() > maxSize ||
        data.size() > static_cast<size_t>(numeric_limits<int>::max()))
        throw invalid_argument("Invalid binary data.");

    if (sqlite3_bind_blob(statement, index, data.data(), static_cast<int>(data.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK)
        throw runtime_error("SQLite bind error: " + lastError(db));
}

Bytes readBlob(sqlite3_stmt* statement, int column) {
    const void* blob = sqlite3_column_blob(statement, column);
    int size = sqlite3_column_bytes(statement, column);

    if (blob == nullptr || size <= 0)
        throw runtime_error("Invalid or empty encrypted data.");

    const auto* bytes = static_cast<const unsigned char*>(blob);
    return Bytes(bytes, bytes + size);
}

// Rejects malformed records BEFORE they reach the database.
void validate(const EncryptedData& data) {
    if (data.version != FORMAT_LEGACY && data.version != FORMAT_BOUND)
        throw invalid_argument("Unsupported encryption format version.");

    if (data.salt.empty() || data.salt.size() > MAX_SMALL_BLOB ||
        data.nonce.empty() || data.nonce.size() > MAX_SMALL_BLOB ||
        data.authTag.empty() || data.authTag.size() > MAX_SMALL_BLOB ||
        data.ciphertext.empty() || data.ciphertext.size() > MAX_CIPHERTEXT)
        throw invalid_argument("Invalid encrypted record.");
}

void validateId(int id) {
    if (id <= 0) throw invalid_argument("Invalid entry ID.");
}

// Columns 1-4 are the blobs, column 5 the format version.
void bindEncrypted(sqlite3_stmt* statement, const EncryptedData& data, bool withVersion,
                   sqlite3* db) {
    validate(data);
    bindBlob(statement, 1, data.salt, MAX_SMALL_BLOB, db);
    bindBlob(statement, 2, data.nonce, MAX_SMALL_BLOB, db);
    bindBlob(statement, 3, data.ciphertext, MAX_CIPHERTEXT, db);
    bindBlob(statement, 4, data.authTag, MAX_SMALL_BLOB, db);
    if (withVersion) bindInt(statement, 5, data.version, db);
}

EncryptedData readEncrypted(sqlite3_stmt* statement, int offset, bool withVersion) {
    EncryptedData data;
    data.salt = readBlob(statement, offset);
    data.nonce = readBlob(statement, offset + 1);
    data.ciphertext = readBlob(statement, offset + 2);
    data.authTag = readBlob(statement, offset + 3);
    data.version = withVersion ? sqlite3_column_int(statement, offset + 4) : FORMAT_LEGACY;
    return data;
}

// BEGIN IMMEDIATE ... COMMIT, rolled back automatically unless commit() succeeded.
// Declared after the statements that use it so statements are finalized first.
class Transaction {
    sqlite3* db_;
    bool active_ = false;

public:
    explicit Transaction(sqlite3* db) : db_(db) {
        execute(db_, "BEGIN IMMEDIATE;", "Could not start transaction");
        active_ = true;
    }

    void commit() {
        execute(db_, "COMMIT;", "Commit failed");
        active_ = false;
    }

    ~Transaction() {
        if (active_) sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    }

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
};

// Updates existing rows; every row must exist (exactly one change).
void updateRows(sqlite3* db, const vector<pair<int, EncryptedData>>& rows) {
    auto statement = prepare(
        db,
        "UPDATE password_entries "
        "SET salt = ?, nonce = ?, ciphertext = ?, auth_tag = ?, format_version = ? "
        "WHERE id = ?;");

    for (const auto& row : rows) {
        validateId(row.first);
        sqlite3_reset(statement.get());
        sqlite3_clear_bindings(statement.get());
        bindEncrypted(statement.get(), row.second, true, db);
        bindInt(statement.get(), 6, row.first, db);

        if (sqlite3_step(statement.get()) != SQLITE_DONE || sqlite3_changes(db) != 1)
            throw runtime_error("Could not re-encrypt record " + to_string(row.first));
    }
}

}  // namespace

// ------------------------------------------------------------- lifecycle
Database::Database(const string& databaseName) : path_(databaseName) {
    if (databaseName.empty() || databaseName.find('\0') != string::npos)
        throw invalid_argument("Database path is empty or invalid.");

    int result = sqlite3_open_v2(databaseName.c_str(), &db,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                     SQLITE_OPEN_FULLMUTEX,
                                 nullptr);

    if (result != SQLITE_OK) {
        string error = db ? sqlite3_errmsg(db) : "Could not allocate SQLite connection.";
        if (db) { sqlite3_close_v2(db); db = nullptr; }
        throw runtime_error("Database connection failed: " + error);
    }

    try {
        sqlite3_busy_timeout(db, 5000);
        execute(db, "PRAGMA secure_delete=ON;", "Could not enable secure_delete");
        execute(db, "PRAGMA foreign_keys=ON;", "Could not enable foreign keys");
    }
    catch (...) {
        sqlite3_close_v2(db);
        db = nullptr;
        throw;
    }
}

Database::~Database() {
    if (db) { sqlite3_close_v2(db); db = nullptr; }
}

bool Database::columnExists(const string& table, const string& column) const {
    auto statement = prepare(db, "SELECT name FROM pragma_table_info('" + table + "');");

    while (true) {
        int result = sqlite3_step(statement.get());
        if (result == SQLITE_DONE) return false;
        if (result != SQLITE_ROW)
            throw runtime_error("Could not inspect table " + table + ": " + lastError(db));

        const unsigned char* name = sqlite3_column_text(statement.get(), 0);
        if (name != nullptr && column == reinterpret_cast<const char*>(name)) return true;
    }
}

void Database::createTables() {
    {
        lock_guard<mutex> guard(mutex_);

        Transaction tx(db);

        execute(db, R"(
            CREATE TABLE IF NOT EXISTS password_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                salt BLOB NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                format_version INTEGER NOT NULL DEFAULT 1
            );
        )", "Table creation failed");

        execute(db, R"(
            CREATE TABLE IF NOT EXISTS vault_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                auth_tag BLOB NOT NULL
            );
        )", "Table creation failed");

        tx.commit();
    }

    // Databases created by earlier versions lack the format_version column.
    // Adding it is purely additive: every existing row becomes format 1, which
    // is exactly how it was encrypted. A backup is written first.
    bool needsColumn;
    {
        lock_guard<mutex> guard(mutex_);
        needsColumn = !columnExists("password_entries", "format_version");
    }

    if (needsColumn) {
        createBackup("pre-schema-v2");

        lock_guard<mutex> guard(mutex_);
        Transaction tx(db);
        execute(db,
                "ALTER TABLE password_entries "
                "ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1;",
                "Schema upgrade failed");
        tx.commit();
    }
}

// ------------------------------------------------------------- backup
string Database::createBackup(const string& label) {
    lock_guard<mutex> guard(mutex_);

    if (path_ == ":memory:" || path_.rfind("file:", 0) == 0)
        throw runtime_error("This database cannot be backed up to a file.");

    string safeLabel;
    for (char c : label)
        safeLabel += (isalnum(static_cast<unsigned char>(c)) || c == '-') ? c : '_';

    auto seconds = chrono::duration_cast<chrono::seconds>(
                       chrono::system_clock::now().time_since_epoch()).count();

    string target;
    for (int attempt = 0; attempt < 1000; attempt++) {
        target = path_ + "." + safeLabel + "-" + to_string(seconds) +
                 (attempt ? "-" + to_string(attempt) : "") + ".bak";
        if (!filesystem::exists(target)) break;
        if (attempt == 999) throw runtime_error("Could not choose a backup file name.");
    }

    sqlite3* copy = nullptr;
    int result = sqlite3_open_v2(target.c_str(), &copy,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    bool ok = false;
    string error;

    if (result == SQLITE_OK) {
        sqlite3_backup* job = sqlite3_backup_init(copy, "main", db, "main");

        if (job != nullptr) {
            int step = sqlite3_backup_step(job, -1);  // copy everything in one pass
            int finish = sqlite3_backup_finish(job);
            ok = (step == SQLITE_DONE && finish == SQLITE_OK);
        }
        if (!ok) error = lastError(copy);
    } else {
        error = copy ? lastError(copy) : "could not open the backup file";
    }

    if (copy) sqlite3_close_v2(copy);

    if (!ok) {
        error_code ignored;
        filesystem::remove(target, ignored);  // never leave a half-written backup behind
        throw runtime_error("Backup failed: " + error);
    }

    return target;
}

// ------------------------------------------------------------- verifier
bool Database::hasVerifier() const {
    lock_guard<mutex> guard(mutex_);
    auto statement = prepare(db, "SELECT COUNT(*) FROM vault_metadata;");

    if (sqlite3_step(statement.get()) != SQLITE_ROW)
        throw runtime_error("Could not read vault metadata: " + lastError(db));

    return sqlite3_column_int(statement.get(), 0) > 0;
}

optional<EncryptedData> Database::loadVerifier() const {
    lock_guard<mutex> guard(mutex_);
    auto statement = prepare(
        db, "SELECT salt, nonce, ciphertext, auth_tag FROM vault_metadata WHERE id = 1;");

    int result = sqlite3_step(statement.get());

    if (result == SQLITE_DONE) return nullopt;
    if (result != SQLITE_ROW)
        throw runtime_error("SQLite read error: " + lastError(db));

    return readEncrypted(statement.get(), 0, false);
}

void Database::saveVerifier(const EncryptedData& verifier) {
    lock_guard<mutex> guard(mutex_);
    auto statement = prepare(
        db,
        "INSERT INTO vault_metadata (id, salt, nonce, ciphertext, auth_tag) "
        "VALUES (1, ?, ?, ?, ?);");

    bindEncrypted(statement.get(), verifier, false, db);

    if (sqlite3_step(statement.get()) != SQLITE_DONE)
        throw runtime_error("Verifier creation failed: " + lastError(db));
}

// ------------------------------------------------------------- records
size_t Database::entryCount() const {
    lock_guard<mutex> guard(mutex_);
    auto statement = prepare(db, "SELECT COUNT(*) FROM password_entries;");

    if (sqlite3_step(statement.get()) != SQLITE_ROW)
        throw runtime_error("Could not count vault entries.");

    return static_cast<size_t>(sqlite3_column_int64(statement.get(), 0));
}

bool Database::insertEntry(const EncryptedData& data) {
    lock_guard<mutex> guard(mutex_);
    auto statement = prepare(
        db,
        "INSERT INTO password_entries (salt, nonce, ciphertext, auth_tag, format_version) "
        "VALUES (?, ?, ?, ?, ?);");

    bindEncrypted(statement.get(), data, true, db);

    if (sqlite3_step(statement.get()) != SQLITE_DONE)
        throw runtime_error("Insert failed: " + lastError(db));

    return true;
}

long long Database::lastInsertId() const {
    lock_guard<mutex> guard(mutex_);
    return sqlite3_last_insert_rowid(db);
}

long long Database::insertSealed(const function<EncryptedData(long long)>& seal) {
    lock_guard<mutex> guard(mutex_);
    Transaction tx(db);  // any exception below rolls the placeholder row back

    long long id = 0;
    {
        // A one-byte placeholder reserves the AUTOINCREMENT id; it is replaced
        // before COMMIT, so it can never be seen by anyone else.
        auto reserve = prepare(
            db,
            "INSERT INTO password_entries (salt, nonce, ciphertext, auth_tag, format_version) "
            "VALUES (x'00', x'00', x'00', x'00', 1);");

        if (sqlite3_step(reserve.get()) != SQLITE_DONE)
            throw runtime_error("Insert failed: " + lastError(db));

        id = sqlite3_last_insert_rowid(db);
    }

    if (id <= 0 || id > numeric_limits<int>::max())
        throw runtime_error("Entry id out of range.");

    vector<pair<int, EncryptedData>> row;
    row.emplace_back(static_cast<int>(id), seal(id));
    updateRows(db, row);

    tx.commit();
    return id;
}

vector<StoredEntry> Database::getAllEntries() const {
    lock_guard<mutex> guard(mutex_);
    vector<StoredEntry> entries;

    auto statement = prepare(
        db,
        "SELECT id, salt, nonce, ciphertext, auth_tag, format_version "
        "FROM password_entries ORDER BY id;");

    while (true) {
        int result = sqlite3_step(statement.get());

        if (result == SQLITE_DONE) break;
        if (result != SQLITE_ROW)
            throw runtime_error("Read failed: " + lastError(db));

        StoredEntry entry;
        entry.id = sqlite3_column_int(statement.get(), 0);
        entry.encryptedData = readEncrypted(statement.get(), 1, true);
        entries.push_back(move(entry));
    }

    return entries;
}

bool Database::updateEntry(int id, const EncryptedData& data) {
    validateId(id);
    lock_guard<mutex> guard(mutex_);

    auto statement = prepare(
        db,
        "UPDATE password_entries "
        "SET salt = ?, nonce = ?, ciphertext = ?, auth_tag = ?, format_version = ? "
        "WHERE id = ?;");

    bindEncrypted(statement.get(), data, true, db);
    bindInt(statement.get(), 6, id, db);

    if (sqlite3_step(statement.get()) != SQLITE_DONE)
        throw runtime_error("Update failed: " + lastError(db));

    return sqlite3_changes(db) > 0;
}

bool Database::deleteEntry(int id) {
    validateId(id);
    lock_guard<mutex> guard(mutex_);

    auto statement = prepare(db, "DELETE FROM password_entries WHERE id = ?;");
    bindInt(statement.get(), 1, id, db);

    if (sqlite3_step(statement.get()) != SQLITE_DONE)
        throw runtime_error("Delete failed: " + lastError(db));

    return sqlite3_changes(db) > 0;
}

bool Database::replaceEntries(const vector<pair<int, EncryptedData>>& rows) {
    lock_guard<mutex> guard(mutex_);
    Transaction tx(db);

    updateRows(db, rows);

    tx.commit();
    return true;
}

bool Database::replaceVault(const vector<pair<int, EncryptedData>>& rows,
                            const EncryptedData& verifier) {
    lock_guard<mutex> guard(mutex_);
    Transaction tx(db);

    updateRows(db, rows);

    auto meta = prepare(
        db,
        "UPDATE vault_metadata "
        "SET salt = ?, nonce = ?, ciphertext = ?, auth_tag = ? WHERE id = 1;");
    bindEncrypted(meta.get(), verifier, false, db);

    if (sqlite3_step(meta.get()) != SQLITE_DONE || sqlite3_changes(db) != 1)
        throw runtime_error("Could not update the master password verifier.");

    tx.commit();
    return true;
}
