#include "EntryStore.h"
#include "Crypto.h"
#include "Errors.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <iostream>
#include <optional>
#include <thread>

using namespace std;

namespace {

string lower(string s) {
    transform(s.begin(), s.end(), s.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return s;
}

long long nowMs() {
    using namespace chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

}  // namespace

void EntryStore::unlock(const string& password) {
    if (password.empty() || password.size() > 1024)
        throw ApiError(400, "Invalid master password.");

    if (!db.hasMasterPassword() && password.size() < 10)
        throw ApiError(400, "Master password must be at least 10 characters.");

    bool ok = false;
    try {
        ok = db.initializeOrVerifyMasterPassword(password);
    } catch (const exception& e) {
        cerr << "Unlock failed: " << e.what() << '\n';
    }
    if (!ok)
        throw ApiError(401, "Could not unlock vault. Check your master password.");

    lock();  // drop any previous session state
    masterPassword = password;
    open = true;
}

void EntryStore::lock() {
    if (!masterPassword.empty())
        OPENSSL_cleanse(masterPassword.data(), masterPassword.size());
    masterPassword.clear();
    cache.clear();
    loaded = false;
    skipped = 0;
    open = false;
}

void EntryStore::ensureLoaded() {
    if (loaded) return;

    vector<StoredEntry> rows = db.getAllEntries();
    vector<optional<Entry>> decoded(rows.size());

    // Each record has its own salt, so decrypt them in parallel.
    atomic<size_t> next{0};
    unsigned workers = max(1u, min(thread::hardware_concurrency(), 8u));
    vector<thread> pool;

    for (unsigned t = 0; t < workers; t++) {
        pool.emplace_back([&] {
            for (size_t i; (i = next++) < rows.size();) {
                try {
                    Entry e = Entry::fromPayload(
                        Crypto::decrypt(rows[i].encryptedData, masterPassword));
                    e.id = rows[i].id;
                    decoded[i] = move(e);
                } catch (const exception& ex) {
                    cerr << "Skipping unreadable record " << rows[i].id
                         << ": " << ex.what() << '\n';
                }
            }
        });
    }
    for (auto& th : pool) th.join();

    cache.clear();
    skipped = 0;
    for (auto& d : decoded) {
        if (d) cache.push_back(move(*d));
        else skipped++;
    }
    loaded = true;
}

Entry* EntryStore::find(int id) {
    ensureLoaded();
    for (auto& e : cache)
        if (e.id == id) return &e;
    return nullptr;
}

const vector<Entry>& EntryStore::list() {
    ensureLoaded();
    return cache;
}

void EntryStore::rejectDuplicate(const Entry& entry, int ignoreId) const {
    if (entry.deleted) return;

    for (const Entry& c : cache) {
        if (c.id == ignoreId || c.deleted || c.type != entry.type) continue;

        if (lower(c.title) == lower(entry.title) &&
            lower(c.field("username")) == lower(entry.field("username")))
            throw ApiError(409, "An item with this title and username already exists.");
    }
}

void EntryStore::persist(const Entry& entry) {
    EncryptedData enc = Crypto::encrypt(entry.toPayload(), masterPassword);

    if (!db.updateEntry(entry.id, enc))
        throw ApiError(404, "Item not found.");
}

Entry EntryStore::add(Entry entry) {
    ensureLoaded();
    rejectDuplicate(entry, 0);

    entry.created = nowMs();
    entry.favorite = false;
    entry.deleted = false;

    EncryptedData enc = Crypto::encrypt(entry.toPayload(), masterPassword);
    if (!db.insertEntry(enc))
        throw runtime_error("Could not save the record to the database.");

    entry.id = static_cast<int>(db.lastInsertId());
    cache.push_back(entry);
    return entry;
}

Entry EntryStore::update(int id, Entry entry) {
    Entry* old = find(id);
    if (!old) throw ApiError(404, "Item not found.");

    entry.id = id;
    entry.favorite = old->favorite;
    entry.deleted = old->deleted;
    entry.created = old->created;

    rejectDuplicate(entry, id);
    persist(entry);

    *old = entry;
    return entry;
}

void EntryStore::setFavorite(int id, bool value) {
    Entry* e = find(id);
    if (!e) throw ApiError(404, "Item not found.");

    Entry changed = *e;
    changed.favorite = value;
    persist(changed);
    *e = changed;
}

void EntryStore::setDeleted(int id, bool value) {
    Entry* e = find(id);
    if (!e) throw ApiError(404, "Item not found.");

    Entry changed = *e;
    changed.deleted = value;
    if (value) changed.favorite = false;
    persist(changed);
    *e = changed;
}

void EntryStore::remove(int id) {
    if (!find(id)) throw ApiError(404, "Item not found.");
    if (!db.deleteEntry(id)) throw ApiError(404, "Item not found.");

    cache.erase(remove_if(cache.begin(), cache.end(),
                          [id](const Entry& e) { return e.id == id; }),
                cache.end());
}
