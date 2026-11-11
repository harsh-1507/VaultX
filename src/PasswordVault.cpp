#include "PasswordVault.h"
#include "Errors.h"
#include "PasswordAnalyzer.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <iostream>
#include <system_error>
#include <thread>

using namespace std;

namespace {

const string VERIFIER_MESSAGE = "VAULTX_MASTER_PASSWORD_VERIFIED_2026";

string lower(string s) {
    transform(s.begin(), s.end(), s.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return s;
}

long long nowMs() {
    using namespace chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void requireStrongMaster(const string& password) {
    if (password.size() < 10)
        throw ApiError(400, "Master password must be at least 10 characters.");

    if (PasswordAnalyzer::analyze(password).score < 40)
        throw ApiError(400,
                       "Master password is too weak. Mix upper and lower case letters, "
                       "numbers and symbols, or use a longer passphrase.");
}

// Runs fn(0) ... fn(jobs-1) on a few threads (the caller helps too). fn must
// handle its own errors; anything that escapes is swallowed so a worker thread
// can never call std::terminate.
template <class Fn>
void runParallel(size_t jobs, Fn&& fn) {
    if (jobs == 0) return;

    atomic<size_t> next{0};
    auto worker = [&] {
        for (size_t i; (i = next++) < jobs;) {
            try { fn(i); } catch (...) {}
        }
    };

    size_t workers = min<size_t>(max(1u, thread::hardware_concurrency()), 8u);
    workers = min(workers, jobs);

    vector<thread> pool;
    for (size_t t = 1; t < workers; t++) {
        try { pool.emplace_back(worker); }
        catch (const system_error&) { break; }  // fewer helpers is fine
    }

    worker();
    for (auto& th : pool) th.join();
}

}  // namespace

Bytes PasswordVault::recordAad(int id) {
    const string text = "VaultX/record/v2/" + to_string(id);
    return Bytes(text.begin(), text.end());
}

// ------------------------------------------------------------------ session
void PasswordVault::requireOpen() const {
    if (!open_) throw ApiError(401, "Vault is locked.");
}

void PasswordVault::ensureLoaded() const {
    requireOpen();
    // Entries are decrypted during unlock(): the master password is not kept,
    // so nothing could be decrypted lazily later.
    if (!loaded_) throw logic_error("Vault session is not loaded.");
}

void PasswordVault::startSession(Bytes salt, Bytes key) {
    lock();  // drop any previous session
    sessionSalt_ = move(salt);
    sessionKey_ = move(key);
    keys_.put(sessionSalt_, sessionKey_);
    lastActive_ = Clock::now();
    open_ = true;
}

void PasswordVault::unlock(const string& password) {
    if (password.empty() || password.size() > 1024)
        throw ApiError(400, "Invalid master password.");

    optional<EncryptedData> verifier = storage_.loadVerifier();

    if (!verifier) {
        // First launch: create the vault.
        requireStrongMaster(password);

        if (storage_.entryCount() > 0)
            throw runtime_error(
                "Existing vault entries found without a master-password verifier. "
                "Refusing to initialize.");

        Bytes salt = cipher_.randomSalt();
        Bytes key = cipher_.deriveKey(password, salt);  // self-wiping on every exit path

        storage_.saveVerifier(cipher_.encryptWithKey(VERIFIER_MESSAGE, key, salt));
        startSession(move(salt), move(key));
    } else {
        Bytes key = cipher_.deriveKey(password, verifier->salt);
        bool ok = false;

        try {
            ok = cipher_.decryptWithKey(*verifier, key) == VERIFIER_MESSAGE;
        } catch (const exception&) {
            ok = false;  // wrong password and corrupt verifier look the same to the caller
        }

        if (!ok) throw ApiError(401, "Could not unlock vault. Check your master password.");

        startSession(verifier->salt, move(key));
    }

    // From here the session is open: if loading fails, fully lock again.
    try {
        loadEntries(password);

        if (autoUpgrade_) {
            try {
                upgradeLegacyRecords();
            } catch (const exception& e) {
                // Not fatal: the vault stays fully usable with the old format.
                cerr << "Record upgrade skipped: " << e.what() << '\n';
            }
        }
    } catch (...) {
        lock();
        throw;
    }
}

void PasswordVault::lock() {
    wipe(sessionKey_);
    wipe(sessionSalt_);
    keys_.clear();

    entries_.clear();  // ~Entry() overwrites titles, notes and field values
    loaded_ = false;
    skipped_ = 0;
    legacyIds_.clear();
    open_ = false;
}

bool PasswordVault::lockIfIdle(chrono::milliseconds limit) {
    if (!open_ || Clock::now() - lastActive_ < limit) return false;

    lock();
    return true;
}

void PasswordVault::changePassword(const string& current, const string& next) {
    requireOpen();

    // Check the current password without keeping it: derive its key again and
    // compare, in constant time, with the key of the live session.
    bool matches = false;
    if (!current.empty() && current.size() <= 1024) {
        Bytes check = cipher_.deriveKey(current, sessionSalt_);
        matches = check.size() == sessionKey_.size() &&
                  CRYPTO_memcmp(check.data(), sessionKey_.data(), check.size()) == 0;
    }
    if (!matches) throw ApiError(403, "Current master password is incorrect.");

    if (next.empty() || next.size() > 1024) throw ApiError(400, "Invalid master password.");
    if (next == current) throw ApiError(400, "The new master password must be different.");
    requireStrongMaster(next);

    ensureLoaded();

    if (skipped_ > 0)
        throw ApiError(409, to_string(skipped_) +
                                " record(s) could not be read and would be lost. "
                                "Nothing was changed.");

    // Re-encrypting only what is in memory would orphan rows that another
    // program added meanwhile, so refuse if the database no longer matches.
    if (storage_.entryCount() != entries_.size())
        throw ApiError(409,
                       "The vault was changed by another program. Lock and unlock it to "
                       "reload, then try again. Nothing was changed.");

    Bytes newSalt = cipher_.randomSalt();
    Bytes newKey = cipher_.deriveKey(next, newSalt);

    vector<pair<int, EncryptedData>> rows;
    rows.reserve(entries_.size());
    for (const auto& e : entries_)
        rows.emplace_back(e->id(), sealWith(*e, newKey, newSalt));  // always the bound format

    EncryptedData verifier = cipher_.encryptWithKey(VERIFIER_MESSAGE, newKey, newSalt);

    // Put the new key in the cache BEFORE the commit, so nothing that can fail
    // is left to do afterwards.
    keys_.put(newSalt, newKey);

    try {
        storage_.replaceVault(rows, verifier);  // all-or-nothing
    } catch (...) {
        keys_.erase(newSalt);
        throw;  // old password, old key and old data are all still in place
    }

    // Committed. Switch the session to the new key; none of these steps throw.
    keys_.retainOnly(newSalt);  // evicts (and cleanses) every old key
    wipe(sessionKey_);
    sessionKey_ = move(newKey);
    sessionSalt_ = move(newSalt);
    legacyIds_.clear();  // everything was just rewritten in the bound format
}

// ------------------------------------------------------------------ loading
void PasswordVault::loadEntries(const string& password) {
    vector<StoredEntry> rows = storage_.getAllEntries();

    // Records created long ago may each have their own salt. The password is
    // not kept, so derive one key per distinct salt NOW (in parallel) and keep
    // only those keys.
    vector<Bytes> salts;
    for (const auto& row : rows) {
        const Bytes& salt = row.encryptedData.salt;
        if (!keys_.contains(salt) && find(salts.begin(), salts.end(), salt) == salts.end())
            salts.push_back(salt);
    }

    runParallel(salts.size(), [&](size_t i) {
        try {
            keys_.ensure(cipher_, password, salts[i]);
        } catch (const exception& ex) {
            cerr << "Could not derive a key for a stored record: " << ex.what() << '\n';
        }
    });

    vector<unique_ptr<Entry>> decoded(rows.size());

    runParallel(rows.size(), [&](size_t i) {
        const StoredEntry& row = rows[i];

        try {
            Bytes aad;
            if (row.encryptedData.version >= FORMAT_BOUND) aad = recordAad(row.id);

            string plain;
            StringWiper wiper(plain);  // plaintext copy is erased even on error

            bool found = keys_.with(row.encryptedData.salt, [&](const Bytes& key) {
                plain = cipher_.decryptWithKey(row.encryptedData, key, aad);
            });
            if (!found) throw runtime_error("no key available for this record");

            unique_ptr<Entry> e = Entry::fromPayload(plain);
            e->setId(row.id);
            decoded[i] = move(e);
        } catch (const exception& ex) {
            cerr << "Skipping unreadable record " << row.id << ": " << ex.what() << '\n';
        }
    });

    entries_.clear();
    skipped_ = 0;
    legacyIds_.clear();

    for (size_t i = 0; i < decoded.size(); i++) {
        if (!decoded[i]) { skipped_++; continue; }
        if (rows[i].encryptedData.version == FORMAT_LEGACY) legacyIds_.insert(rows[i].id);
        entries_.push_back(move(decoded[i]));
    }

    loaded_ = true;
}

size_t PasswordVault::upgradeLegacyRecords() {
    ensureLoaded();
    if (legacyIds_.empty()) return 0;

    // Only records that were read successfully are rewritten; unreadable ones
    // are not in legacyIds_ and are left exactly as they are.
    vector<pair<int, EncryptedData>> upgraded;

    for (const auto& slot : entries_)
        if (legacyIds_.count(slot->id()) > 0) upgraded.emplace_back(slot->id(), seal(*slot));

    if (upgraded.empty()) return 0;

    lastBackup_ = storage_.createBackup("pre-aad-upgrade");  // throws -> nothing changes
    storage_.replaceEntries(upgraded);                       // all-or-nothing

    for (const auto& row : upgraded) legacyIds_.erase(row.first);
    return upgraded.size();
}

unique_ptr<Entry>* PasswordVault::findSlot(int id) {
    ensureLoaded();
    for (auto& slot : entries_)
        if (slot->id() == id) return &slot;
    return nullptr;
}

const vector<unique_ptr<Entry>>& PasswordVault::list() {
    ensureLoaded();
    return entries_;
}

const Entry& PasswordVault::get(int id) {
    auto* slot = findSlot(id);
    if (!slot) throw ApiError(404, "Item not found.");
    return **slot;
}

// ------------------------------------------------------------------ changes
void PasswordVault::rejectDuplicate(const Entry& entry, int ignoreId) const {
    if (entry.deleted()) return;

    for (const auto& other : entries_) {
        if (other->id() == ignoreId || other->deleted() || other->type() != entry.type())
            continue;

        if (lower(other->title()) == lower(entry.title()) &&
            lower(other->field("username")) == lower(entry.field("username")))
            throw ApiError(409, "An item with this title and username already exists.");
    }
}

EncryptedData PasswordVault::sealWith(const Entry& entry, const Bytes& key,
                                      const Bytes& salt) const {
    string payload = entry.toPayload();
    StringWiper wiper(payload);

    // The record id is authenticated: moving this ciphertext to another id fails.
    return cipher_.encryptWithKey(payload, key, salt, recordAad(entry.id()));
}

EncryptedData PasswordVault::seal(const Entry& entry) {
    return sealWith(entry, sessionKey_, sessionSalt_);
}

void PasswordVault::persist(const Entry& entry) {
    if (!storage_.updateEntry(entry.id(), seal(entry)))
        throw ApiError(404, "Item not found.");

    legacyIds_.erase(entry.id());  // it was just written in the bound format
}

const Entry& PasswordVault::add(unique_ptr<Entry> entry) {
    ensureLoaded();
    if (!entry) throw ApiError(400, "Invalid item.");

    entry->validate();
    rejectDuplicate(*entry, 0);

    entry->setCreated(nowMs());
    entry->setFavorite(false);
    entry->setDeleted(false);

    // The id is needed for the AAD, so the storage reserves it, calls us back
    // to encrypt, and commits - or stores nothing at all.
    long long id = storage_.insertSealed([&](long long newId) {
        entry->setId(static_cast<int>(newId));
        return seal(*entry);
    });

    entry->setId(static_cast<int>(id));
    entries_.push_back(move(entry));
    return *entries_.back();
}

const Entry& PasswordVault::update(int id, unique_ptr<Entry> entry) {
    auto* slot = findSlot(id);
    if (!slot) throw ApiError(404, "Item not found.");
    if (!entry) throw ApiError(400, "Invalid item.");

    entry->validate();
    entry->setId(id);
    entry->setFavorite((*slot)->favorite());
    entry->setDeleted((*slot)->deleted());
    entry->setCreated((*slot)->created());

    rejectDuplicate(*entry, id);
    persist(*entry);  // writes the bound format, so legacy records upgrade here

    *slot = move(entry);
    return **slot;
}

void PasswordVault::setFavorite(int id, bool value) {
    auto* slot = findSlot(id);
    if (!slot) throw ApiError(404, "Item not found.");

    unique_ptr<Entry> changed = (*slot)->clone();  // polymorphic copy
    changed->setFavorite(value);
    persist(*changed);
    *slot = move(changed);
}

void PasswordVault::setDeleted(int id, bool value) {
    auto* slot = findSlot(id);
    if (!slot) throw ApiError(404, "Item not found.");

    unique_ptr<Entry> changed = (*slot)->clone();
    changed->setDeleted(value);
    if (value) changed->setFavorite(false);
    persist(*changed);
    *slot = move(changed);
}

void PasswordVault::remove(int id) {
    if (!findSlot(id)) throw ApiError(404, "Item not found.");
    if (!storage_.deleteEntry(id)) throw ApiError(404, "Item not found.");

    legacyIds_.erase(id);

    entries_.erase(remove_if(entries_.begin(), entries_.end(),
                             [id](const unique_ptr<Entry>& e) { return e->id() == id; }),
                   entries_.end());
}
