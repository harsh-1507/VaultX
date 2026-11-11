#ifndef SECUREMEMORY_H
#define SECUREMEMORY_H

#include <openssl/crypto.h>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

using namespace std;

// Allocator that overwrites memory with OPENSSL_cleanse() before releasing it.
// Any container that uses it wipes its buffer on destruction AND when it
// reallocates, so temporary copies of keys cannot linger on the heap.
template <class T>
struct CleansingAllocator {
    using value_type = T;

    CleansingAllocator() noexcept = default;
    template <class U>
    CleansingAllocator(const CleansingAllocator<U>&) noexcept {}

    T* allocate(size_t count) { return allocator<T>().allocate(count); }

    void deallocate(T* pointer, size_t count) noexcept {
        if (pointer != nullptr) OPENSSL_cleanse(pointer, count * sizeof(T));
        allocator<T>().deallocate(pointer, count);
    }

    template <class U>
    bool operator==(const CleansingAllocator<U>&) const noexcept { return true; }
    template <class U>
    bool operator!=(const CleansingAllocator<U>&) const noexcept { return false; }
};

// Byte buffer used for salts, nonces, ciphertext and (above all) keys.
using Bytes = vector<unsigned char, CleansingAllocator<unsigned char>>;

// Overwrite the contents in place. The object stays valid and becomes empty.
inline void wipe(Bytes& bytes) {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    bytes.clear();
}

inline void wipe(string& text) {
    if (!text.empty()) OPENSSL_cleanse(&text[0], text.size());
    text.clear();
}

// RAII: wipes a string when the scope ends, including when an exception flies.
class StringWiper {
    string& text_;

public:
    explicit StringWiper(string& text) : text_(text) {}
    ~StringWiper() { wipe(text_); }

    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;
};

#endif
