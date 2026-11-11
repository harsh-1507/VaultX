#ifndef ENTRYSTORE_H
#define ENTRYSTORE_H

#include <string>
#include <vector>

#include "Database.h"
#include "Entry.h"

// Encrypted storage for Entry objects. Keeps a decrypted cache while the
// vault is unlocked so the (slow) key derivation runs once per record, not on
// every request. NOT thread-safe: the caller must serialize access.
class EntryStore {
    Database& db;
    std::string masterPassword;
    bool open = false;
    bool loaded = false;
    size_t skipped = 0;
    std::vector<Entry> cache;

    void ensureLoaded();
    Entry* find(int id);
    void persist(const Entry& entry);
    void rejectDuplicate(const Entry& entry, int ignoreId) const;

public:
    explicit EntryStore(Database& database) : db(database) {}
    ~EntryStore() { lock(); }

    bool isUnlocked() const { return open; }
    void unlock(const std::string& password);  // throws ApiError(401/400)
    void lock();

    const std::vector<Entry>& list();
    size_t skippedCount() const { return skipped; }

    Entry add(Entry entry);
    Entry update(int id, Entry entry);
    void setFavorite(int id, bool value);
    void setDeleted(int id, bool value);
    void remove(int id);
};

#endif
