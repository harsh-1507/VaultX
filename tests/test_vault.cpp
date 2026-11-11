// PasswordVault tests: sessions, master password, id-bound encryption (AAD),
// migration of old-format records, atomicity, auto-lock and the key cache.
// Uses FastCipher (same AES-GCM, cheaper key derivation) except where noted.

#include <iomanip>
#include <thread>

#include "Database.h"
#include "EntryTypes.h"
#include "KeyCache.h"
#include "PasswordVault.h"
#include "TestFramework.h"
#include "TestSupport.h"

using namespace std;

namespace {

unique_ptr<Entry> login(const string& title, const string& user = "alice",
                        const string& password = "Sup3r-Secret!") {
    auto entry = make_unique<LoginEntry>();
    entry->setTitle(title);
    entry->setField("username", user);
    entry->setField("password", password);
    return entry;
}

// Database + cipher + vault on one file. Destroying it and creating another
// one on the same path is a "restart of the application".
struct App {
    Database db;
    FastCipher cipher;
    PasswordVault vault;

    explicit App(const string& path) : db(path), vault(init(db), cipher) {}

private:
    static Database& init(Database& d) { d.createTables(); return d; }
};

// Writes a record in the OLD format (no AAD, its own random salt) exactly the
// way the previous VaultX version did.
void insertLegacy(Database& db, const Cipher& cipher, const Entry& entry, const string& password) {
    db.insertEntry(cipher.encrypt(entry.toPayload(), password));
}

vector<int> versionsInDb(Database& db) {
    vector<int> v;
    for (auto& row : db.getAllEntries()) v.push_back(row.encryptedData.version);
    return v;
}

size_t filesWithSuffix(const TempDir& dir, const string& needle) {
    size_t n = 0;
    for (auto& f : filesystem::directory_iterator(dir.path()))
        if (f.path().string().find(needle) != string::npos) n++;
    return n;
}

}  // namespace

// ---------------------------------------------------------------- session
TEST_CASE(vault_initialization) {
    TempDir dir;
    App app(dir.file("v.db"));

    CHECK(!app.vault.isInitialized());
    CHECK(!app.vault.isUnlocked());

    CHECK_EQ(errorCode([&] { app.vault.unlock("short"); }), 400);
    CHECK_EQ(errorCode([&] { app.vault.unlock("aaaaaaaaaaaa"); }), 400);  // long but weak
    CHECK(!app.vault.isInitialized());  // failed attempts create nothing

    app.vault.unlock(strongPassword());  // first unlock creates the vault
    CHECK(app.vault.isInitialized());
    CHECK(app.vault.isUnlocked());
    CHECK(app.vault.list().empty());
}

TEST_CASE(correct_and_incorrect_master_password) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());
    app.vault.lock();

    CHECK_EQ(errorCode([&] { app.vault.unlock("Wrong-Password-123!"); }), 401);
    CHECK(!app.vault.isUnlocked());
    CHECK_EQ(errorCode([&] { app.vault.unlock(""); }), 400);
    CHECK_EQ(errorCode([&] { app.vault.unlock(string(2000, 'x')); }), 400);
    CHECK(!app.vault.isUnlocked());

    app.vault.unlock(strongPassword());
    CHECK(app.vault.isUnlocked());
}

TEST_CASE(locking_blocks_everything_and_unlocking_restores) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());
    int id = app.vault.add(login("Mail")).id();

    app.vault.lock();
    CHECK(!app.vault.isUnlocked());

    CHECK_EQ(errorCode([&] { app.vault.list(); }), 401);
    CHECK_EQ(errorCode([&] { app.vault.get(id); }), 401);
    CHECK_EQ(errorCode([&] { app.vault.add(login("X")); }), 401);
    CHECK_EQ(errorCode([&] { app.vault.update(id, login("X")); }), 401);
    CHECK_EQ(errorCode([&] { app.vault.setFavorite(id, true); }), 401);
    CHECK_EQ(errorCode([&] { app.vault.setDeleted(id, true); }), 401);
    CHECK_EQ(errorCode([&] { app.vault.remove(id); }), 401);
    CHECK_EQ(errorCode([&] { app.vault.changePassword(strongPassword(), otherStrongPassword()); }), 401);
    app.vault.lock();  // locking twice is harmless
    CHECK_EQ(app.db.entryCount(), 1u);  // nothing was changed while locked

    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.get(id).title(), string("Mail"));
}

TEST_CASE(unlock_again_while_unlocked_restarts_the_session) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());
    app.vault.add(login("Mail"));
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 1u);
    CHECK_EQ(errorCode([&] { app.vault.unlock("Wrong-Password-123!"); }), 401);
    CHECK(app.vault.isUnlocked());  // a wrong attempt does not end a good session
}

// ---------------------------------------------------------------- entries
TEST_CASE(entry_create_read_update_delete) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());

    const Entry& saved = app.vault.add(login("Mail", "alice"));
    int id = saved.id();
    CHECK(id > 0);
    CHECK(saved.created() > 0);
    CHECK_EQ(app.vault.get(id).field("password"), string("Sup3r-Secret!"));
    CHECK_EQ(app.vault.list().size(), 1u);

    app.vault.setFavorite(id, true);
    const Entry& edited = app.vault.update(id, login("Mail 2", "alice2", "N3w-Password!"));
    CHECK_EQ(edited.title(), string("Mail 2"));
    CHECK_EQ(edited.field("password"), string("N3w-Password!"));
    CHECK(edited.favorite());  // edits keep flags and creation time
    CHECK_EQ(edited.created(), saved.created());

    CHECK_EQ(errorCode([&] { app.vault.update(999, login("Nope")); }), 404);
    CHECK_EQ(errorCode([&] { app.vault.get(999); }), 404);
    CHECK_EQ(errorCode([&] { app.vault.remove(999); }), 404);

    app.vault.remove(id);
    CHECK(app.vault.list().empty());
    CHECK_EQ(app.db.entryCount(), 0u);
    CHECK_EQ(errorCode([&] { app.vault.get(id); }), 404);
}

TEST_CASE(duplicates_and_invalid_entries_are_rejected) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());
    app.vault.add(login("Mail", "alice"));

    CHECK_EQ(errorCode([&] { app.vault.add(login("MAIL", "ALICE")); }), 409);
    app.vault.add(login("Mail", "bob"));  // different username is fine

    CHECK_EQ(errorCode([&] { app.vault.add(login("", "alice")); }), 400);
    CHECK_EQ(errorCode([&] { app.vault.add(login("T", "u", "123")); }), 400);  // password too short
    CHECK_EQ(errorCode([&] { app.vault.add(nullptr); }), 400);
    CHECK_EQ(app.db.entryCount(), 2u);
}

TEST_CASE(favorites_trash_and_restore_persist_across_restart) {
    TempDir dir;
    string path = dir.file("v.db");
    int a, b;
    {
        App app(path);
        app.vault.unlock(strongPassword());
        a = app.vault.add(login("A")).id();
        b = app.vault.add(login("B")).id();

        app.vault.setFavorite(a, true);
        app.vault.setFavorite(b, true);
        app.vault.setDeleted(b, true);  // trashing also clears the favourite flag
        CHECK(app.vault.get(a).favorite());
        CHECK(app.vault.get(b).deleted());
        CHECK(!app.vault.get(b).favorite());
    }

    App app(path);  // restart
    app.vault.unlock(strongPassword());
    CHECK(app.vault.get(a).favorite());
    CHECK(!app.vault.get(a).deleted());
    CHECK(app.vault.get(b).deleted());

    app.vault.setDeleted(b, false);  // restore
    app.vault.setFavorite(a, false);
    app.vault.lock();
    app.vault.unlock(strongPassword());
    CHECK(!app.vault.get(b).deleted());
    CHECK(!app.vault.get(a).favorite());
}

TEST_CASE(entries_survive_a_restart_with_all_fields) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        App app(path);
        app.vault.unlock(strongPassword());
        auto e = login("Bank", "carol", "p@ss-w0rd-123");
        e->setNotes("remember the PIN");
        e->setFolder("Finance");
        app.vault.add(std::move(e));
    }

    App app(path);
    app.vault.unlock(strongPassword());
    const Entry& e = *app.vault.list()[0];
    CHECK_EQ(e.title(), string("Bank"));
    CHECK_EQ(e.folder(), string("Finance"));
    CHECK_EQ(e.notes(), string("remember the PIN"));
    CHECK_EQ(e.field("username"), string("carol"));
    CHECK_EQ(e.field("password"), string("p@ss-w0rd-123"));
}

// ---------------------------------------------------------------- change password
TEST_CASE(master_password_change_preserves_entries) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        App app(path);
        app.vault.unlock(strongPassword());
        app.vault.add(login("One", "u1"));
        app.vault.add(login("Two", "u2"));
        app.vault.add(login("Three", "u3"));
        app.vault.setFavorite(2, true);

        app.vault.changePassword(strongPassword(), otherStrongPassword());

        // The session keeps working with the new key, without re-entering anything.
        CHECK_EQ(app.vault.list().size(), 3u);
        app.vault.add(login("Four", "u4"));
        app.vault.update(1, login("One edited", "u1"));

        for (int v : versionsInDb(app.db)) CHECK_EQ(v, FORMAT_BOUND);  // everything is id-bound now
    }

    App app(path);  // restart: only the NEW password works
    CHECK_EQ(errorCode([&] { app.vault.unlock(strongPassword()); }), 401);
    app.vault.unlock(otherStrongPassword());
    CHECK_EQ(app.vault.list().size(), 4u);
    CHECK_EQ(app.vault.skippedCount(), 0u);
    CHECK_EQ(app.vault.get(1).title(), string("One edited"));
    CHECK(app.vault.get(2).favorite());
    CHECK_EQ(app.vault.get(3).field("password"), string("Sup3r-Secret!"));
}

TEST_CASE(master_password_change_validation) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());
    app.vault.add(login("One"));

    CHECK_EQ(errorCode([&] { app.vault.changePassword("Wrong-Current-123!", otherStrongPassword()); }), 403);
    CHECK_EQ(errorCode([&] { app.vault.changePassword("", otherStrongPassword()); }), 403);
    CHECK_EQ(errorCode([&] { app.vault.changePassword(strongPassword(), "weak"); }), 400);
    CHECK_EQ(errorCode([&] { app.vault.changePassword(strongPassword(), strongPassword()); }), 400);
    CHECK_EQ(errorCode([&] { app.vault.changePassword(strongPassword(), string(2000, 'x')); }), 400);

    app.vault.lock();
    app.vault.unlock(strongPassword());  // still the original password
    CHECK_EQ(app.vault.list().size(), 1u);
}

TEST_CASE(master_password_change_is_atomic) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        Database db(path);
        db.createTables();
        FailingCipher cipher;
        PasswordVault vault(db, cipher);
        vault.unlock(strongPassword());
        vault.add(login("One", "u1"));
        vault.add(login("Two", "u2"));
        vault.add(login("Three", "u3"));

        cipher.calls = 0;
        cipher.failOnCall = 2;  // fail while re-encrypting the second record
        CHECK_THROWS_AS(vault.changePassword(strongPassword(), otherStrongPassword()), runtime_error);

        cipher.failOnCall = 0;
        CHECK(vault.isUnlocked());
        CHECK_EQ(vault.list().size(), 3u);
        vault.add(login("Four", "u4"));  // the session is still fully usable with the OLD key
    }

    App app(path);
    CHECK_EQ(errorCode([&] { app.vault.unlock(otherStrongPassword()); }), 401);  // nothing was changed
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 4u);
    CHECK_EQ(app.vault.skippedCount(), 0u);
}

TEST_CASE(master_password_change_refuses_when_records_are_unreadable) {
    TempDir dir;
    string path = dir.file("v.db");
    App app(path);
    app.vault.unlock(strongPassword());
    app.vault.add(login("One"));
    app.vault.lock();

    EncryptedData junk = app.cipher.encrypt("{\"title\":\"x\"}", "some-other-password");
    app.db.insertEntry(junk);  // a record this master password cannot open

    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.skippedCount(), 1u);
    CHECK_EQ(errorCode([&] { app.vault.changePassword(strongPassword(), otherStrongPassword()); }), 409);

    CHECK_EQ(app.db.entryCount(), 2u);  // the unreadable record is still there
    app.vault.lock();
    app.vault.unlock(strongPassword());  // and the password did not change
    CHECK(app.vault.isUnlocked());
}

TEST_CASE(master_password_change_refuses_when_database_changed_elsewhere) {
    TempDir dir;
    string path = dir.file("v.db");
    App app(path);
    app.vault.unlock(strongPassword());
    app.vault.add(login("One"));

    Database other(path);  // another program adds a record behind the vault's back
    other.insertEntry(app.cipher.encrypt("{\"title\":\"x\"}", strongPassword()));

    CHECK_EQ(errorCode([&] { app.vault.changePassword(strongPassword(), otherStrongPassword()); }), 409);
    app.vault.lock();
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size() + app.vault.skippedCount(), 2u);  // nothing lost
}

// ---------------------------------------------------------------- AAD binding
TEST_CASE(new_records_are_bound_to_their_id) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());
    app.vault.add(login("A"));
    app.vault.setFavorite(1, true);

    for (int v : versionsInDb(app.db)) CHECK_EQ(v, FORMAT_BOUND);
}

TEST_CASE(swapping_ciphertext_between_records_is_detected_not_deleted) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        App app(path);
        app.vault.unlock(strongPassword());
        app.vault.add(login("A", "ua"));
        app.vault.add(login("B", "ub"));
    }

    // Attacker / bug: exchange the encrypted contents of record 1 and 2.
    rawSql(path, R"(
        CREATE TEMP TABLE t AS SELECT * FROM password_entries WHERE id IN (1, 2);
        UPDATE password_entries SET
            salt       = (SELECT salt       FROM t WHERE t.id = 3 - password_entries.id),
            nonce      = (SELECT nonce      FROM t WHERE t.id = 3 - password_entries.id),
            ciphertext = (SELECT ciphertext FROM t WHERE t.id = 3 - password_entries.id),
            auth_tag   = (SELECT auth_tag   FROM t WHERE t.id = 3 - password_entries.id)
        WHERE id IN (1, 2);
    )");

    App app(path);
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 0u);      // neither record is accepted
    CHECK_EQ(app.vault.skippedCount(), 2u);     // ...they are reported...
    CHECK_EQ(app.db.entryCount(), 2u);          // ...and kept on disk
}

TEST_CASE(copying_a_record_to_a_new_id_is_detected) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        App app(path);
        app.vault.unlock(strongPassword());
        app.vault.add(login("A"));
    }

    rawSql(path, R"(
        INSERT INTO password_entries (salt, nonce, ciphertext, auth_tag, format_version)
        SELECT salt, nonce, ciphertext, auth_tag, format_version FROM password_entries WHERE id = 1;
    )");

    App app(path);
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 1u);  // the original still opens
    CHECK_EQ(app.vault.skippedCount(), 1u); // the copy (id 2) does not
    CHECK_EQ(app.vault.list()[0]->id(), 1);
}

TEST_CASE(changing_a_record_id_is_detected) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        App app(path);
        app.vault.unlock(strongPassword());
        app.vault.add(login("A"));
    }
    rawSql(path, "UPDATE password_entries SET id = 77 WHERE id = 1;");

    App app(path);
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 0u);
    CHECK_EQ(app.vault.skippedCount(), 1u);
}

TEST_CASE(downgrading_the_format_flag_does_not_bypass_the_binding) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        App app(path);
        app.vault.unlock(strongPassword());
        app.vault.add(login("A"));
    }
    rawSql(path, "UPDATE password_entries SET format_version = 1;");

    App app(path);
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.skippedCount(), 1u);  // authentication fails: the tag covers the AAD
}

TEST_CASE(tampered_data_is_skipped_and_never_destroyed) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        App app(path);
        app.vault.unlock(strongPassword());
        app.vault.add(login("A"));
        app.vault.add(login("B"));
    }
    rawSql(path, "UPDATE password_entries SET ciphertext = x'00' || substr(ciphertext, 2) WHERE id = 1;");

    App app(path);
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 1u);
    CHECK_EQ(app.vault.skippedCount(), 1u);

    // Normal work continues and never rewrites or deletes the unreadable row.
    app.vault.add(login("C"));
    app.vault.update(2, login("B2"));
    CHECK_EQ(app.db.entryCount(), 3u);
    CHECK_EQ(errorCode([&] { app.vault.remove(1); }), 404);  // it is not addressable through the vault
    CHECK_EQ(app.db.entryCount(), 3u);
}

// ---------------------------------------------------------------- migration
TEST_CASE(legacy_records_stay_readable_and_upgrade_when_edited) {
    TempDir dir;
    string path = dir.file("v.db");
    App app(path);
    app.vault.unlock(strongPassword());
    app.vault.lock();

    // Two records the way the OLD version stored them: no AAD, a salt per record.
    insertLegacy(app.db, app.cipher, *login("Old One", "o1"), strongPassword());
    insertLegacy(app.db, app.cipher, *login("Old Two", "o2"), strongPassword());
    CHECK(app.db.getAllEntries()[0].encryptedData.salt != app.db.getAllEntries()[1].encryptedData.salt);

    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 2u);   // different salts: both keys were derived at unlock
    CHECK_EQ(app.vault.skippedCount(), 0u);
    CHECK_EQ(app.vault.legacyCount(), 2u);
    CHECK_EQ(app.vault.get(1).field("password"), string("Sup3r-Secret!"));

    // Nothing is rewritten just by reading.
    CHECK_EQ(versionsInDb(app.db)[0], FORMAT_LEGACY);
    CHECK_EQ(filesWithSuffix(dir, ".bak"), 0u);

    // Editing a record writes it in the bound format.
    app.vault.update(1, login("Old One edited", "o1"));
    CHECK_EQ(versionsInDb(app.db)[0], FORMAT_BOUND);
    CHECK_EQ(versionsInDb(app.db)[1], FORMAT_LEGACY);
    CHECK_EQ(app.vault.legacyCount(), 1u);

    app.vault.lock();
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 2u);
    CHECK_EQ(app.vault.legacyCount(), 1u);
}

TEST_CASE(bulk_upgrade_makes_a_backup_and_is_complete) {
    TempDir dir;
    string path = dir.file("v.db");
    App app(path);
    app.vault.unlock(strongPassword());
    app.vault.add(login("New", "n1"));  // already bound
    app.vault.lock();
    insertLegacy(app.db, app.cipher, *login("Old One", "o1"), strongPassword());
    insertLegacy(app.db, app.cipher, *login("Old Two", "o2"), strongPassword());

    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.legacyCount(), 2u);
    CHECK_EQ(app.vault.upgradeLegacyRecords(), 2u);

    CHECK_EQ(app.vault.legacyCount(), 0u);
    for (int v : versionsInDb(app.db)) CHECK_EQ(v, FORMAT_BOUND);
    CHECK(filesystem::exists(app.vault.lastBackupPath()));
    CHECK_EQ(filesWithSuffix(dir, "pre-aad-upgrade"), 1u);
    CHECK_EQ(app.vault.upgradeLegacyRecords(), 0u);  // nothing left to do

    // The backup is the pre-upgrade state: it still contains legacy-format rows.
    Database backup(app.vault.lastBackupPath());
    size_t legacyInBackup = 0;
    for (int v : versionsInDb(backup)) legacyInBackup += (v == FORMAT_LEGACY);
    CHECK_EQ(legacyInBackup, 2u);

    app.vault.lock();
    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 3u);
    CHECK_EQ(app.vault.skippedCount(), 0u);
}

TEST_CASE(upgrade_never_touches_unreadable_records) {
    TempDir dir;
    string path = dir.file("v.db");
    App app(path);
    app.vault.unlock(strongPassword());
    app.vault.lock();
    insertLegacy(app.db, app.cipher, *login("Old", "o"), strongPassword());
    insertLegacy(app.db, app.cipher, *login("Foreign", "f"), "a-different-master-password");

    vector<StoredEntry> before = app.db.getAllEntries();

    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.skippedCount(), 1u);
    CHECK_EQ(app.vault.upgradeLegacyRecords(), 1u);

    vector<StoredEntry> after = app.db.getAllEntries();
    CHECK_EQ(after.size(), 2u);
    CHECK(after[1].encryptedData.ciphertext == before[1].encryptedData.ciphertext);  // byte-identical
    CHECK(after[1].encryptedData.salt == before[1].encryptedData.salt);
    CHECK_EQ(after[1].encryptedData.version, FORMAT_LEGACY);
}

TEST_CASE(automatic_upgrade_only_runs_when_enabled) {
    TempDir dir;
    string path = dir.file("v.db");
    App app(path);
    app.vault.unlock(strongPassword());
    app.vault.lock();
    insertLegacy(app.db, app.cipher, *login("Old", "o"), strongPassword());

    app.vault.unlock(strongPassword());  // default: off
    CHECK_EQ(versionsInDb(app.db)[0], FORMAT_LEGACY);
    CHECK_EQ(filesWithSuffix(dir, ".bak"), 0u);
    app.vault.lock();

    app.vault.setAutoUpgrade(true);
    app.vault.unlock(strongPassword());
    CHECK_EQ(versionsInDb(app.db)[0], FORMAT_BOUND);
    CHECK_EQ(filesWithSuffix(dir, "pre-aad-upgrade"), 1u);
}

TEST_CASE(oldest_cli_payload_format_is_still_readable) {
    TempDir dir;
    string path = dir.file("v.db");
    App app(path);
    app.vault.unlock(strongPassword());
    app.vault.lock();

    // Format written by the very first console version: four quoted strings.
    ostringstream payload;
    payload << quoted("Netflix") << ' ' << quoted("dave") << ' ' << quoted("old-pass-1") << ' '
            << quoted("Social");
    app.db.insertEntry(app.cipher.encrypt(payload.str(), strongPassword()));

    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 1u);
    CHECK_EQ(app.vault.list()[0]->title(), string("Netflix"));
    CHECK_EQ(app.vault.list()[0]->field("password"), string("old-pass-1"));
}

// ---------------------------------------------------------------- failure handling
TEST_CASE(failed_add_leaves_no_partial_record) {
    TempDir dir;
    string path = dir.file("v.db");
    Database db(path);
    db.createTables();
    FailingCipher cipher;
    PasswordVault vault(db, cipher);
    vault.unlock(strongPassword());

    cipher.calls = 0;
    cipher.failOnCall = 1;
    CHECK_THROWS_AS(vault.add(login("A")), runtime_error);
    cipher.failOnCall = 0;

    CHECK_EQ(db.entryCount(), 0u);            // no half-written row
    CHECK(vault.list().empty());              // nor an in-memory ghost
    CHECK_EQ(vault.add(login("A")).id(), 1);  // and the id was not wasted
}

TEST_CASE(failed_update_keeps_the_old_record) {
    TempDir dir;
    string path = dir.file("v.db");
    Database db(path);
    db.createTables();
    FailingCipher cipher;
    PasswordVault vault(db, cipher);
    vault.unlock(strongPassword());
    int id = vault.add(login("Original")).id();

    cipher.calls = 0;
    cipher.failOnCall = 1;
    CHECK_THROWS_AS(vault.update(id, login("Changed")), runtime_error);
    CHECK_THROWS_AS(vault.setFavorite(id, true), runtime_error);
    cipher.failOnCall = 0;

    CHECK_EQ(vault.get(id).title(), string("Original"));
    CHECK(!vault.get(id).favorite());
    vault.lock();
    vault.unlock(strongPassword());
    CHECK_EQ(vault.get(id).title(), string("Original"));
}

// ---------------------------------------------------------------- auto-lock
TEST_CASE(auto_lock_after_idle_time) {
    TempDir dir;
    App app(dir.file("v.db"));
    CHECK(!app.vault.lockIfIdle(chrono::milliseconds(0)));  // nothing to lock yet

    app.vault.unlock(strongPassword());
    app.vault.add(login("A"));

    CHECK(!app.vault.lockIfIdle(chrono::hours(1)));  // recently used: stays open
    CHECK(app.vault.isUnlocked());

    this_thread::sleep_for(chrono::milliseconds(60));
    CHECK(app.vault.lockIfIdle(chrono::milliseconds(30)));  // idle for longer than the limit
    CHECK(!app.vault.isUnlocked());
    CHECK_EQ(errorCode([&] { app.vault.list(); }), 401);    // and it is really locked
    CHECK(!app.vault.lockIfIdle(chrono::milliseconds(0)));  // already locked: nothing to do

    app.vault.unlock(strongPassword());
    CHECK_EQ(app.vault.list().size(), 1u);
}

TEST_CASE(activity_postpones_auto_lock) {
    TempDir dir;
    App app(dir.file("v.db"));
    app.vault.unlock(strongPassword());

    this_thread::sleep_for(chrono::milliseconds(50));
    app.vault.touch();  // an authenticated request just happened
    CHECK(!app.vault.lockIfIdle(chrono::milliseconds(40)));
    CHECK(app.vault.isUnlocked());

    this_thread::sleep_for(chrono::milliseconds(60));
    CHECK(app.vault.lockIfIdle(chrono::milliseconds(40)));
}

// ---------------------------------------------------------------- production cipher
TEST_CASE(real_cipher_end_to_end) {
    TempDir dir;
    string path = dir.file("v.db");
    {
        Database db(path);
        db.createTables();
        AesGcmCipher cipher;  // production parameters: 600,000 PBKDF2 rounds
        PasswordVault vault(db, cipher);
        vault.unlock(strongPassword());
        vault.add(login("Real", "r"));
    }

    Database db(path);
    db.createTables();
    AesGcmCipher cipher;
    PasswordVault vault(db, cipher);
    CHECK_EQ(errorCode([&] { vault.unlock("Wrong-Password-123!"); }), 401);
    vault.unlock(strongPassword());
    CHECK_EQ(vault.get(1).field("password"), string("Sup3r-Secret!"));
}

// ---------------------------------------------------------------- KeyCache
TEST_CASE(key_cache_stores_reads_and_evicts) {
    KeyCache cache;
    FastCipher cipher;
    Bytes salt1 = cipher.randomSalt(), salt2 = cipher.randomSalt(), salt3 = cipher.randomSalt();
    Bytes key1(32, 1), key2(32, 2), key3(32, 3);

    CHECK(!cache.contains(salt1));
    CHECK(!cache.with(salt1, [](const Bytes&) {}));

    cache.put(salt1, key1);
    cache.put(salt2, key2);
    cache.put(salt3, key3);
    CHECK_EQ(cache.size(), 3u);

    Bytes seen;
    CHECK(cache.with(salt2, [&](const Bytes& k) { seen = k; }));
    CHECK(seen == key2);

    cache.put(salt2, key3);  // replacing a key overwrites it
    cache.with(salt2, [&](const Bytes& k) { seen = k; });
    CHECK(seen == key3);

    cache.erase(salt1);
    CHECK(!cache.contains(salt1));

    cache.retainOnly(salt3);  // password change: every other key goes
    CHECK_EQ(cache.size(), 1u);
    CHECK(cache.contains(salt3));

    cache.clear();  // lock: nothing may remain usable
    CHECK_EQ(cache.size(), 0u);
    CHECK(!cache.with(salt3, [](const Bytes&) {}));
}

TEST_CASE(key_cache_derives_once_per_salt) {
    KeyCache cache;
    FastCipher cipher;
    Bytes salt = cipher.randomSalt();

    cache.ensure(cipher, "some-password-1", salt);
    Bytes first;
    cache.with(salt, [&](const Bytes& k) { first = k; });
    CHECK(first == cipher.deriveKey("some-password-1", salt));

    cache.ensure(cipher, "a-different-password", salt);  // already cached: not derived again
    Bytes second;
    cache.with(salt, [&](const Bytes& k) { second = k; });
    CHECK(first == second);
}

TEST_CASE(key_cache_is_safe_under_concurrent_use) {
    KeyCache cache;
    FastCipher cipher;
    vector<Bytes> salts;
    for (int i = 0; i < 4; i++) salts.push_back(cipher.randomSalt());

    vector<thread> pool;
    for (int t = 0; t < 8; t++)
        pool.emplace_back([&] {
            for (const Bytes& s : salts) cache.ensure(cipher, "concurrent-password", s);
        });
    for (auto& th : pool) th.join();

    CHECK_EQ(cache.size(), 4u);
}
