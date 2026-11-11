// Database tests. Every test uses its own temporary database file; the real
// vaultx.db is never opened.

#include <sqlite3.h>

#include <atomic>
#include <filesystem>
#include <set>
#include <thread>

#include "Database.h"
#include "TestFramework.h"
#include "TestSupport.h"

using namespace std;

namespace {

EncryptedData sample(unsigned char fill = 1, int version = FORMAT_LEGACY) {
    EncryptedData d;
    d.salt = Bytes(16, fill);
    d.nonce = Bytes(12, static_cast<unsigned char>(fill + 1));
    d.ciphertext = Bytes(40, static_cast<unsigned char>(fill + 2));
    d.authTag = Bytes(16, static_cast<unsigned char>(fill + 3));
    d.version = version;
    return d;
}

bool same(const EncryptedData& a, const EncryptedData& b) {
    return a.salt == b.salt && a.nonce == b.nonce && a.ciphertext == b.ciphertext &&
           a.authTag == b.authTag && a.version == b.version;
}

}  // namespace

TEST_CASE(initialization_is_idempotent) {
    TempDir dir;
    Database db(dir.file("v.db"));

    db.createTables();
    db.createTables();  // running it again must be harmless

    CHECK(!db.hasVerifier());
    CHECK(!db.loadVerifier().has_value());
    CHECK_EQ(db.entryCount(), 0u);
    CHECK(db.getAllEntries().empty());
    CHECK(filesystem::exists(dir.file("v.db")));
}

TEST_CASE(fresh_database_needs_no_migration_backup) {
    TempDir dir;
    {
        Database db(dir.file("v.db"));
        db.createTables();
    }
    int files = 0;
    for (auto& f : filesystem::directory_iterator(dir.path()))
        if (f.path().extension() == ".bak") files++;
    CHECK_EQ(files, 0);
}

TEST_CASE(verifier_roundtrip_and_single_row) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();

    db.saveVerifier(sample(7));
    CHECK(db.hasVerifier());

    auto loaded = db.loadVerifier();
    CHECK(loaded.has_value());
    CHECK(same(*loaded, sample(7)));

    CHECK_THROWS(db.saveVerifier(sample(9)));  // only one verifier may exist
    CHECK(same(*db.loadVerifier(), sample(7)));
}

TEST_CASE(entry_create_and_retrieve) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();

    CHECK(db.insertEntry(sample(10)));
    long long first = db.lastInsertId();
    CHECK(db.insertEntry(sample(20, FORMAT_BOUND)));
    long long second = db.lastInsertId();

    CHECK_EQ(second, first + 1);
    CHECK_EQ(db.entryCount(), 2u);

    vector<StoredEntry> all = db.getAllEntries();
    CHECK_EQ(all.size(), 2u);
    CHECK_EQ(all[0].id, static_cast<int>(first));
    CHECK(same(all[0].encryptedData, sample(10)));
    CHECK(same(all[1].encryptedData, sample(20, FORMAT_BOUND)));  // version is stored
}

TEST_CASE(entry_edit) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();
    db.insertEntry(sample(1));
    int id = static_cast<int>(db.lastInsertId());

    CHECK(db.updateEntry(id, sample(50, FORMAT_BOUND)));
    CHECK(same(db.getAllEntries()[0].encryptedData, sample(50, FORMAT_BOUND)));
    CHECK(!db.updateEntry(id + 100, sample(2)));  // unknown id: reported, nothing created
    CHECK_EQ(db.entryCount(), 1u);
}

TEST_CASE(entry_delete) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();
    db.insertEntry(sample(1));
    db.insertEntry(sample(2));
    int id = static_cast<int>(db.getAllEntries()[0].id);

    CHECK(db.deleteEntry(id));
    CHECK(!db.deleteEntry(id));  // already gone
    CHECK_EQ(db.entryCount(), 1u);
}

TEST_CASE(invalid_ids_and_data_are_rejected) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();

    CHECK_THROWS_AS(db.updateEntry(0, sample()), invalid_argument);
    CHECK_THROWS_AS(db.updateEntry(-5, sample()), invalid_argument);
    CHECK_THROWS_AS(db.deleteEntry(0), invalid_argument);

    EncryptedData bad = sample();
    bad.ciphertext.clear();
    CHECK_THROWS_AS(db.insertEntry(bad), invalid_argument);

    bad = sample();
    bad.salt = Bytes(65, 1);  // far larger than any salt
    CHECK_THROWS_AS(db.insertEntry(bad), invalid_argument);

    bad = sample();
    bad.version = 9;
    CHECK_THROWS_AS(db.insertEntry(bad), invalid_argument);

    CHECK_EQ(db.entryCount(), 0u);  // nothing got stored

    CHECK_THROWS_AS(Database(""), invalid_argument);
    CHECK_THROWS(Database(dir.file("no_such_folder/x.db")));
}

TEST_CASE(insert_sealed_receives_its_own_id) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();

    long long seen = 0;
    long long id = db.insertSealed([&](long long newId) {
        seen = newId;
        return sample(33, FORMAT_BOUND);
    });

    CHECK(id > 0);
    CHECK_EQ(seen, id);
    CHECK_EQ(db.entryCount(), 1u);
    CHECK_EQ(db.getAllEntries()[0].id, static_cast<int>(id));
    CHECK(same(db.getAllEntries()[0].encryptedData, sample(33, FORMAT_BOUND)));  // placeholder replaced
}

TEST_CASE(transaction_rollback_when_sealing_fails) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();

    long long first = db.insertSealed([](long long) { return sample(1, FORMAT_BOUND); });

    CHECK_THROWS(db.insertSealed([](long long) -> EncryptedData {
        throw runtime_error("encryption failed half way");
    }));
    CHECK_EQ(db.entryCount(), 1u);  // no partial record

    // Invalid data from the sealer is also rolled back.
    CHECK_THROWS_AS(db.insertSealed([](long long) { EncryptedData d = sample(); d.nonce.clear(); return d; }),
                    invalid_argument);
    CHECK_EQ(db.entryCount(), 1u);

    // The failed attempts did not burn an id.
    long long next = db.insertSealed([](long long) { return sample(2, FORMAT_BOUND); });
    CHECK_EQ(next, first + 1);
}

TEST_CASE(transaction_rollback_in_replace_vault) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();
    db.saveVerifier(sample(1));
    db.insertEntry(sample(10));
    db.insertEntry(sample(20));
    vector<StoredEntry> before = db.getAllEntries();

    // Second row does not exist: the first row's change must be undone as well.
    vector<pair<int, EncryptedData>> rows;
    rows.emplace_back(before[0].id, sample(77, FORMAT_BOUND));
    rows.emplace_back(9999, sample(88, FORMAT_BOUND));

    CHECK_THROWS(db.replaceVault(rows, sample(99)));

    vector<StoredEntry> after = db.getAllEntries();
    CHECK(same(after[0].encryptedData, before[0].encryptedData));
    CHECK(same(after[1].encryptedData, before[1].encryptedData));
    CHECK(same(*db.loadVerifier(), sample(1)));  // verifier untouched too

    // replaceEntries is atomic as well.
    CHECK_THROWS(db.replaceEntries(rows));
    CHECK(same(db.getAllEntries()[0].encryptedData, before[0].encryptedData));

    // And the successful path really replaces everything.
    rows.clear();
    rows.emplace_back(before[0].id, sample(70, FORMAT_BOUND));
    rows.emplace_back(before[1].id, sample(71, FORMAT_BOUND));
    CHECK(db.replaceVault(rows, sample(99)));
    CHECK(same(db.getAllEntries()[1].encryptedData, sample(71, FORMAT_BOUND)));
    CHECK(same(*db.loadVerifier(), sample(99)));
}

TEST_CASE(a_failed_transaction_does_not_block_later_work) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();
    db.insertEntry(sample(1));

    vector<pair<int, EncryptedData>> rows;
    rows.emplace_back(424242, sample(5));
    CHECK_THROWS(db.replaceEntries(rows));

    // If the failed transaction were still open, this BEGIN would fail.
    CHECK(db.insertEntry(sample(2)));
    CHECK_EQ(db.entryCount(), 2u);
}

TEST_CASE(data_persists_after_restart) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        Database db(path);
        db.createTables();
        db.saveVerifier(sample(4));
        db.insertEntry(sample(5));
        db.insertEntry(sample(6, FORMAT_BOUND));
    }  // connection closed

    Database db(path);
    db.createTables();  // existing tables and rows must survive this

    CHECK(db.hasVerifier());
    CHECK(same(*db.loadVerifier(), sample(4)));
    vector<StoredEntry> all = db.getAllEntries();
    CHECK_EQ(all.size(), 2u);
    CHECK(same(all[0].encryptedData, sample(5)));
    CHECK(same(all[1].encryptedData, sample(6, FORMAT_BOUND)));
}

TEST_CASE(old_schema_is_migrated_with_backup_and_no_data_loss) {
    TempDir dir;
    string path = dir.file("old.db");

    // The exact table layout written by the previous VaultX version.
    rawSql(path, R"(
        CREATE TABLE password_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, salt BLOB NOT NULL,
            nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, auth_tag BLOB NOT NULL);
        CREATE TABLE vault_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), salt BLOB NOT NULL,
            nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, auth_tag BLOB NOT NULL);
        INSERT INTO password_entries (salt, nonce, ciphertext, auth_tag)
            VALUES (x'0102030405060708090a0b0c0d0e0f10', x'aabbccddeeff001122334455', x'deadbeefcafebabe00', x'11223344556677889900aabbccddeeff');
        INSERT INTO vault_metadata (id, salt, nonce, ciphertext, auth_tag)
            VALUES (1, x'0102030405060708090a0b0c0d0e0f10', x'aabbccddeeff001122334455', x'deadbeef01', x'11223344556677889900aabbccddeeff');
    )");

    Database db(path);
    db.createTables();  // adds format_version

    vector<StoredEntry> rows = db.getAllEntries();
    CHECK_EQ(rows.size(), 1u);
    CHECK_EQ(rows[0].encryptedData.version, FORMAT_LEGACY);  // old rows are format 1
    CHECK_EQ(rows[0].encryptedData.ciphertext.size(), 9u);
    CHECK(db.hasVerifier());

    // A backup of the pre-migration file was written and holds the original row.
    string backup;
    for (auto& f : filesystem::directory_iterator(dir.path()))
        if (f.path().string().find("pre-schema-v2") != string::npos) backup = f.path().string();
    CHECK(!backup.empty());

    Database copy(backup);
    CHECK_EQ(copy.entryCount(), 1u);

    db.createTables();  // second run: no further backup
    int backups = 0;
    for (auto& f : filesystem::directory_iterator(dir.path()))
        if (f.path().extension() == ".bak") backups++;
    CHECK_EQ(backups, 1);
}

TEST_CASE(backup_is_a_complete_copy) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();
    db.saveVerifier(sample(1));
    db.insertEntry(sample(2));
    db.insertEntry(sample(3, FORMAT_BOUND));

    string backup = db.createBackup("manual test!");  // odd characters in the label are sanitized
    CHECK(filesystem::exists(backup));
    CHECK(backup.find(' ') == string::npos);

    Database copy(backup);
    CHECK_EQ(copy.entryCount(), 2u);
    CHECK(same(copy.getAllEntries()[1].encryptedData, sample(3, FORMAT_BOUND)));
    CHECK(same(*copy.loadVerifier(), sample(1)));

    string second = db.createBackup("manual test!");
    CHECK(second != backup);  // never overwrites an earlier backup
}

TEST_CASE(concurrent_access_from_many_threads) {
    TempDir dir;
    Database db(dir.file("v.db"));
    db.createTables();

    constexpr int THREADS = 8, PER_THREAD = 25;
    atomic<int> failures{0};
    mutex idMutex;
    set<long long> ids;

    vector<thread> pool;
    for (int t = 0; t < THREADS; t++) {
        pool.emplace_back([&, t] {
            for (int i = 0; i < PER_THREAD; i++) {
                try {
                    long long id = db.insertSealed([&](long long) {
                        return sample(static_cast<unsigned char>(t + 1), FORMAT_BOUND);
                    });
                    lock_guard<mutex> g(idMutex);
                    ids.insert(id);
                    (void)db.getAllEntries().size();  // readers interleave with writers
                } catch (...) {
                    failures++;
                }
            }
        });
    }
    for (auto& th : pool) th.join();

    CHECK_EQ(failures.load(), 0);
    CHECK_EQ(ids.size(), static_cast<size_t>(THREADS * PER_THREAD));  // all ids unique
    CHECK_EQ(db.entryCount(), static_cast<size_t>(THREADS * PER_THREAD));
}

TEST_CASE(second_connection_sees_committed_changes) {
    TempDir dir;
    Database a(dir.file("v.db"));
    a.createTables();
    Database b(dir.file("v.db"));  // e.g. the CLI and the server on the same file

    a.insertEntry(sample(1));
    CHECK_EQ(b.entryCount(), 1u);
    b.insertEntry(sample(2));
    CHECK_EQ(a.entryCount(), 2u);
}
