#ifndef PASSWORDVAULT_H
#define PASSWORDVAULT_H

#include <chrono>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "Crypto.h"
#include "Entry.h"
#include "KeyCache.h"
#include "Storage.h"

using namespace std;

// The vault: owns the unlocked session and all decrypted entries.
//
// It depends only on the abstract Storage and Cipher interfaces, and works
// with entries polymorphically through the Entry base class.
// NOT thread-safe: callers must serialize access (the web server does).
//
// Secrets while unlocked: the master password is used only inside unlock() /
// changePassword() and is never stored. What stays in memory is the derived
// session key (plus one key per distinct salt found in the database, in the
// KeyCache) and the decrypted entries. lock() wipes all of it.
class PasswordVault {
    using Clock = chrono::steady_clock;

    Storage& storage_;
    const Cipher& cipher_;

    bool open_ = false;
    bool loaded_ = false;
    bool autoUpgrade_ = false;
    size_t skipped_ = 0;  // records that could not be decrypted (never deleted)
    unordered_set<int> legacyIds_;  // readable records still in the old (unbound) format
    string lastBackup_;
    Clock::time_point lastActive_ = Clock::now();

    Bytes sessionSalt_;
    Bytes sessionKey_;
    KeyCache keys_;

    vector<unique_ptr<Entry>> entries_;

    void requireOpen() const;
    void ensureLoaded() const;
    void loadEntries(const string& password);
    unique_ptr<Entry>* findSlot(int id);
    EncryptedData sealWith(const Entry& entry, const Bytes& key, const Bytes& salt) const;
    EncryptedData seal(const Entry& entry);
    void persist(const Entry& entry);
    void rejectDuplicate(const Entry& entry, int ignoreId) const;
    void startSession(Bytes salt, Bytes key);

public:
    PasswordVault(Storage& storage, const Cipher& cipher)
        : storage_(storage), cipher_(cipher) {}
    ~PasswordVault() { lock(); }

    PasswordVault(const PasswordVault&) = delete;
    PasswordVault& operator=(const PasswordVault&) = delete;

    // The additional authenticated data that binds a v2 record to its id.
    static Bytes recordAad(int id);

    bool isInitialized() const { return storage_.hasVerifier(); }
    bool isUnlocked() const { return open_; }

    void unlock(const string& password);  // creates the vault on first use
    void lock();
    void changePassword(const string& current, const string& next);

    // Auto-lock support: the server calls touch() on every authenticated
    // request and lockIfIdle() from its watcher thread.
    void touch() { lastActive_ = Clock::now(); }
    bool lockIfIdle(chrono::milliseconds limit);

    // Old-format records are upgraded to the id-bound format when they are
    // next edited, or all at once by upgradeLegacyRecords() (which writes a
    // backup first and is all-or-nothing). With setAutoUpgrade(true) the bulk
    // upgrade also runs automatically at every unlock. Off by default.
    void setAutoUpgrade(bool enabled) { autoUpgrade_ = enabled; }
    size_t legacyCount() const { return legacyIds_.size(); }
    size_t upgradeLegacyRecords();
    const string& lastBackupPath() const { return lastBackup_; }

    const vector<unique_ptr<Entry>>& list();
    size_t skippedCount() const { return skipped_; }
    const Entry& get(int id);

    const Entry& add(unique_ptr<Entry> entry);
    const Entry& update(int id, unique_ptr<Entry> entry);
    void setFavorite(int id, bool value);
    void setDeleted(int id, bool value);
    void remove(int id);
};

#endif
