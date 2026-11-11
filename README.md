# VaultX

A local, single-user encrypted vault. C++17 backend (Crow + SQLite + OpenSSL) with a plain HTML/CSS/JS frontend.

- **Encryption:** AES-256-GCM, key derived per record with PBKDF2-HMAC-SHA256 (600,000 iterations). Everything about an item (title, fields, notes, favorite/trash flags) is inside the encrypted payload.
- **Item types:** Login, Secure Note, Card, Identity, API Key, Wi-Fi, each with its own fields and validation (see `src/Entry.cpp`).
- **Local only:** the server binds to 127.0.0.1 and locks itself after 15 idle minutes.

## Build

Needs OpenSSL, SQLite3 and asio dev packages, plus Crow in `third_party/Crow`.

    cmake -B build && cmake --build build
    ./build/vaultx_server        # run from the project folder

Open http://127.0.0.1:18080. On first run you create your master password (10+ characters).

Never commit `vaultx.db`. This is a personal/educational project and has not been independently audited.
