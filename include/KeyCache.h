#ifndef KEYCACHE_H
#define KEYCACHE_H

#include <openssl/crypto.h>

#include <map>
#include <mutex>
#include <string>

#include "Crypto.h"

using namespace std;

// Thread-safe cache of derived keys (salt -> key), so the slow key derivation
// runs once per salt instead of once per record.
//
// Protection of the cached keys:
//  * values are `Bytes`, whose allocator wipes the buffer when it is freed;
//  * every removal (clear / retainOnly / destructor) cleanses the key first;
//  * lookups use with(), which hands the caller a const reference while the
//    lock is held, so reading a key never creates another copy;
//  * the cache never stores the password itself.
// Keys are NOT locked into RAM (no mlock/VirtualLock), so the OS may swap them.
class KeyCache {
    mutable mutex mutex_;
    map<Bytes, Bytes> keys_;

    static void cleanse(Bytes& key) {
        if (!key.empty()) OPENSSL_cleanse(key.data(), key.size());
    }

public:
    KeyCache() = default;
    ~KeyCache() { clear(); }

    KeyCache(const KeyCache&) = delete;
    KeyCache& operator=(const KeyCache&) = delete;

    bool contains(const Bytes& salt) const {
        lock_guard<mutex> guard(mutex_);
        return keys_.find(salt) != keys_.end();
    }

    size_t size() const {
        lock_guard<mutex> guard(mutex_);
        return keys_.size();
    }

    // Runs fn(key) while the lock is held. Returns false if the salt is unknown.
    // fn must not call back into this cache.
    template <class Fn>
    bool with(const Bytes& salt, Fn&& fn) const {
        lock_guard<mutex> guard(mutex_);
        auto it = keys_.find(salt);
        if (it == keys_.end()) return false;
        fn(static_cast<const Bytes&>(it->second));
        return true;
    }

    // Derives (slow, outside the lock) and stores the key if it is not cached.
    // Returns nothing on purpose: callers read the key through with().
    void ensure(const Cipher& cipher, const string& password, const Bytes& salt) {
        if (contains(salt)) return;

        Bytes key = cipher.deriveKey(password, salt);  // wiped automatically when it leaves scope

        lock_guard<mutex> guard(mutex_);
        keys_.emplace(salt, key);  // no-op if another thread got there first
    }

    void put(const Bytes& salt, const Bytes& key) {
        lock_guard<mutex> guard(mutex_);
        auto it = keys_.find(salt);
        if (it != keys_.end()) {
            cleanse(it->second);
            it->second = key;
        } else {
            keys_.emplace(salt, key);
        }
    }

    // Evicts every key except the one for `salt` (used after a password change).
    void retainOnly(const Bytes& salt) {
        lock_guard<mutex> guard(mutex_);
        for (auto it = keys_.begin(); it != keys_.end();) {
            if (it->first == salt) {
                ++it;
            } else {
                cleanse(it->second);
                it = keys_.erase(it);
            }
        }
    }

    void erase(const Bytes& salt) {
        lock_guard<mutex> guard(mutex_);
        auto it = keys_.find(salt);
        if (it == keys_.end()) return;
        cleanse(it->second);
        keys_.erase(it);
    }

    void clear() {
        lock_guard<mutex> guard(mutex_);
        for (auto& kv : keys_) cleanse(kv.second);
        keys_.clear();
    }
};

#endif
