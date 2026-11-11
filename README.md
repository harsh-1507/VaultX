# VaultX

**A local, single-user, encrypted password and credential manager written in object-oriented C++17.**

Built with **Crow** (REST API), **SQLite**, **OpenSSL** and a plain **HTML / CSS / Vanilla JS** frontend, with a console (CLI) version that shares the same vault.

**Made by Harsh Lotiya** · GitHub: [@harsh-1507](https://github.com/harsh-1507)

> Personal / educational project. It has **not** been independently security-audited. Do not rely on it as your only copy of important credentials.

---

## Table of contents

1. [Features](#features)
2. [Project status (read this first)](#project-status-read-this-first)
3. [Folder structure](#folder-structure)
4. [Requirements](#requirements)
5. [Setup on Windows (MSYS2 UCRT64)](#setup-on-windows-msys2-ucrt64)
6. [Build with CMake](#build-with-cmake)
7. [Build without CMake (PowerShell / MinGW)](#build-without-cmake-powershell--mingw)
8. [Running VaultX](#running-vaultx)
9. [Configuration (environment variables)](#configuration-environment-variables)
10. [Running the tests](#running-the-tests)
11. [Architecture and OOP design](#architecture-and-oop-design)
12. [Security design](#security-design)
13. [Encryption format and migration](#encryption-format-and-migration)
14. [REST API](#rest-api)
15. [Known limitations](#known-limitations)
16. [Interview talking points](#interview-talking-points)
17. [Author](#author)

---

## Features

- Six item types: **Login, Secure Note, Card, Identity, API Key, Wi-Fi** (added by writing one `Entry` subclass).
- Folders, favourites, trash and restore, duplicate detection.
- Password strength analysis, reuse detection and a cryptographically secure password generator.
- Master-password change that re-encrypts the whole vault in **one atomic transaction**.
- Web UI (`frontend/`) and a console app, both on the same database.
- Server binds to `127.0.0.1` only, validates `Host` / `Origin`, throttles unlock attempts and auto-locks after 15 idle minutes.

## Project status (read this first)

This repository went through a backend security and reliability audit. This table states exactly what is done and what is **not**, so nothing is overstated.

| Area | Status | How it was checked |
|---|---|---|
| Master password no longer stored in memory | Done | Unit tests (`test_vault`) |
| Self-wiping key buffers (`CleansingAllocator`), `KeyCache` rewrite | Done | Unit tests |
| AES-256-GCM record-ID binding (AAD) + format versioning | Done | Unit tests, incl. a fixture produced by the original code |
| Safe migration of existing records (backup first, opt-in bulk upgrade) | Done | Unit tests |
| Database rewrite (RAII transactions, validation, mutex, backup, schema migration) | Done | Unit tests (16 cases) |
| Database location resolver (`VAULTX_DB`, app-data opt-in) | Done | Compiled; used by the CLI |
| `LoginThrottle` rewrite, `ApiValidation` helpers (separate files) | Written and compiled | Not yet wired into `ApiServer` |
| Auto-lock logic inside `PasswordVault` | Done | Unit tests |
| **`ApiServer` rewrite (clean shutdown instead of detached thread, request limits, ID validation)** | **NOT done yet** | `ApiServer.cpp` is still the original |
| **API integration tests, CMake/CTest wiring for tests** | **NOT done yet** | - |

Measured test results (built and run on Linux, GCC 13.3, real OpenSSL / SQLite libraries):

| Suite | Result |
|---|---|
| `test_crypto` | 12 / 12 passed |
| `test_database` | 16 / 16 passed |
| `test_vault` | 31 / 32 passed. The one failure, `failed_update_keeps_the_old_record`, is a bug in the **test** (the failure-injecting cipher only fails on one numbered call, so the second assertion never fails). It is not yet fixed. |

Honest caveats:
- `ApiServer.cpp`, `server.cpp` and the web UI were **not compiled or run** in the audit environment (Crow and asio were unavailable there). Build them yourself with the commands below. The vault, database and crypto code were compiled against the real OpenSSL and SQLite libraries, but `Entry` JSON handling was exercised through a small stand-in for Crow's JSON header, not the real one.
- Until `ApiServer` is updated, the detached idle-watcher thread issue and the missing request-size limits still exist.

## Folder structure

```
VaultX/
├── CMakeLists.txt
├── README.md
├── include/                     class declarations
│   ├── ApiServer.h              HTTP layer (Crow routes, middleware)
│   ├── ApiValidation.h          request checks: ids, JSON depth, static names
│   ├── Crypto.h                 Cipher (abstract), AesGcmCipher, EncryptedData
│   ├── Database.h               SQLite implementation of Storage
│   ├── DatabaseLocation.h       where the .db file lives
│   ├── Entry.h / EntryTypes.h   Entry (abstract) + 6 concrete types + factory
│   ├── Errors.h                 ApiError (carries an HTTP status)
│   ├── KeyCache.h               thread-safe cache of derived keys
│   ├── LoginThrottle.h          unlock-attempt throttling
│   ├── PasswordAnalyzer.h / PasswordGenerator.h
│   ├── PasswordVault.h          the unlocked session and all entries
│   ├── SecureMemory.h           self-wiping Bytes, wipe(), StringWiper
│   └── Storage.h                persistence interface (abstract)
├── src/                         implementations + two entry points
│   ├── server.cpp               web entry point
│   └── main.cpp                 console entry point
├── tests/                       dependency-free test suite (see below)
├── frontend/                    index.html, css/style.css, js/app.js
└── third_party/Crow/            Crow (you clone it, see setup)
```

## Requirements

| Requirement | Version |
|---|---|
| C++ compiler with C++17 and `<filesystem>` | GCC 9+ (developed with GCC 13) |
| CMake (optional, for the CMake build) | 3.16+ |
| OpenSSL | 3.x (development headers) |
| SQLite3 | 3.16+ (development headers) |
| asio (standalone, header-only) | any recent version |
| Crow (header-only) | 1.x, placed in `third_party/Crow` |
| Git | any |

Windows is supported through **MSYS2 UCRT64**. Linux and macOS work with the same sources.

## Setup on Windows (MSYS2 UCRT64)

1. Install MSYS2 from <https://www.msys2.org> and open the **MSYS2 UCRT64** terminal.
2. Install the toolchain and libraries:

```bash
pacman -Syu
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                   mingw-w64-ucrt-x86_64-cmake \
                   mingw-w64-ucrt-x86_64-ninja \
                   mingw-w64-ucrt-x86_64-openssl \
                   mingw-w64-ucrt-x86_64-sqlite3 \
                   mingw-w64-ucrt-x86_64-asio \
                   git
```

3. Get the project and Crow:

```bash
git clone https://github.com/harsh-1507/<your-repo-name>.git VaultX
cd VaultX
git clone --depth 1 https://github.com/CrowCpp/Crow.git third_party/Crow
```

4. For PowerShell, add the UCRT64 tools to `PATH` for the session (adjust the path if MSYS2 is installed elsewhere):

```powershell
$env:Path = "C:\msys64\ucrt64\bin;" + $env:Path
g++ --version
```

**Linux (Debian/Ubuntu):**

```bash
sudo apt install build-essential cmake libssl-dev libsqlite3-dev libasio-dev git
git clone --depth 1 https://github.com/CrowCpp/Crow.git third_party/Crow
```

## Build with CMake

```bash
# configure + build (Release)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Debug build
cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

Without Ninja, drop `-G Ninja` (on MSYS2 use `-G "MinGW Makefiles"`). Outputs: `build/vaultx_server` (web + API) and `build/vaultx_cli` (console); `.exe` on Windows.

## Build without CMake (PowerShell / MinGW)

Run from the project root, with the UCRT64 `bin` folder on `PATH` (see setup step 4).

**Web server:**

```powershell
g++ -std=c++17 -O2 -Iinclude -Ithird_party/Crow/include src/server.cpp src/Crypto.cpp src/Database.cpp src/DatabaseLocation.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp src/PasswordGenerator.cpp src/ApiServer.cpp -o vaultx_server.exe -lssl -lcrypto -lsqlite3 -lws2_32 -lmswsock
```

**Console app:**

```powershell
g++ -std=c++17 -O2 -Iinclude -Ithird_party/Crow/include src/main.cpp src/Crypto.cpp src/Database.cpp src/DatabaseLocation.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp src/PasswordGenerator.cpp src/ApiServer.cpp -o vaultx_cli.exe -lssl -lcrypto -lsqlite3 -lws2_32 -lmswsock
```

On Linux/macOS use the same commands, remove `-lws2_32 -lmswsock`, add `-lpthread`, and drop `.exe`.

## Running VaultX

Run from the **project folder** so the server can find `frontend/`.

```powershell
.\build\vaultx_server.exe        # or .\vaultx_server.exe
# open http://127.0.0.1:18080
.\build\vaultx_cli.exe           # console version, same vault
```

On the first launch you create the vault by choosing a master password (at least 10 characters and not weak). **If you forget it, the data cannot be recovered.**

## Configuration (environment variables)

| Variable | Meaning |
|---|---|
| `VAULTX_DB` | Explicit database path. Always wins. |
| `VAULTX_USE_APPDATA=1` | Use the per-user data folder (`%APPDATA%\VaultX\vaultx.db` on Windows, `$XDG_DATA_HOME/vaultx` or `~/.local/share/vaultx` on Linux). |
| `VAULTX_UPGRADE_RECORDS=1` | Opt in to upgrading old-format records at each unlock (a backup is written first). Off by default. |

Default (nothing set): `vaultx.db` in the folder you start VaultX from, exactly as before. The default never changes by itself and existing databases are never moved or deleted.

```powershell
$env:VAULTX_DB = "D:\VaultXData\vaultx.db"
.\vaultx_server.exe
```

## Running the tests

The tests need no external framework (`tests/TestFramework.h` is a small self-contained harness) and only ever use temporary databases, **never your real `vaultx.db`**.

Compile and run (PowerShell or Linux; add `-lws2_32 -lmswsock` on Windows, `-lpthread` on Linux):

```powershell
# Crypto
g++ -std=c++17 -O1 -Iinclude -Itests -Ithird_party/Crow/include tests/test_main.cpp tests/test_crypto.cpp src/Crypto.cpp -o test_crypto -lssl -lcrypto -lsqlite3
./test_crypto

# Database
g++ -std=c++17 -O1 -Iinclude -Itests -Ithird_party/Crow/include tests/test_main.cpp tests/test_database.cpp src/Crypto.cpp src/Database.cpp -o test_database -lssl -lcrypto -lsqlite3
./test_database

# PasswordVault + KeyCache
g++ -std=c++17 -O1 -Iinclude -Itests -Ithird_party/Crow/include tests/test_main.cpp tests/test_vault.cpp src/Crypto.cpp src/Database.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp -o test_vault -lssl -lcrypto -lsqlite3
./test_vault
```

Pass a name fragment to run a subset, e.g. `./test_vault auto_lock`. Each executable exits non-zero if any case fails.

What is covered:
- **Crypto:** round trip, wrong key, modified ciphertext / tag / nonce, AAD mismatch, downgrade attempt, random salt and nonce uniqueness, and decryption of a record produced by the original pre-AAD code.
- **Database:** initialization, create/read/edit/delete, invalid ids and data, rollback on failure, restart persistence, old-schema migration with backup, backup copy, 8-thread concurrent access.
- **PasswordVault:** initialization, correct/incorrect password, lock/unlock, CRUD, favourites/trash/restore, password change (success, validation, atomicity, refusal cases), AAD tampering (swapped, copied, renumbered, downgraded records), legacy migration, auto-lock, key cache.

CMake/CTest wiring for these tests and the API integration tests are **not added yet** (see status).

## Architecture and OOP design

| Concept | Where |
|---|---|
| **Abstraction** | `Cipher`, `Storage`, `Entry` are abstract interfaces |
| **Inheritance** | `AesGcmCipher : Cipher`, `Database : Storage`, `LoginEntry`, `SecureNoteEntry`, `CardEntry`, `IdentityEntry`, `ApiKeyEntry`, `WifiEntry` : `CloneableEntry<T>` : `Entry` |
| **Polymorphism** | `PasswordVault` and `ApiServer` use `unique_ptr<Entry>` and virtual functions; the vault depends only on `Storage&` and `const Cipher&` |
| **Encapsulation** | private state in `PasswordVault`, `Database`, `KeyCache`, `LoginThrottle` |
| **Patterns** | Factory (`EntryFactory`), Template Method (`Cipher::encrypt`), CRTP (`CloneableEntry`), Prototype (`Entry::clone`), RAII (SQLite statements and transactions, OpenSSL contexts, `StringWiper`, `CleansingAllocator`) |

Flow: `server.cpp` / `main.cpp` create `Database` + `AesGcmCipher` -> `PasswordVault` -> `ApiServer` (web) or `ConsoleApp` (terminal). Because the vault only sees interfaces, the tests swap in a faster `FastCipher` and a failure-injecting `FailingCipher` without changing any production code.

## Security design

- **Encryption:** AES-256-GCM, fresh random 96-bit nonce per encryption. Keys from PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt.
- **Master password is never stored.** It is used only inside `unlock()` / `changePassword()`. The session keeps the derived key only; changing the password verifies the old one by re-deriving and comparing in constant time (`CRYPTO_memcmp`).
- **Key hygiene:** all binary buffers use `CleansingAllocator` (wipes with `OPENSSL_cleanse` on free and on reallocation), so temporary key copies are erased on every exit path, including exceptions. `KeyCache` hands out keys by reference under a lock and cleanses on evict, lock and password change. `Entry`'s destructor overwrites decrypted text (best effort). `lock()` clears everything.
- **Record binding:** each v2 record authenticates its database id as AAD, so moving, copying or renumbering ciphertext fails authentication.
- **Atomicity:** record insert, password change and format upgrade are single transactions. Unreadable records are **never deleted or rewritten**, and a password change is refused if any record is unreadable or the database changed under the vault.
- **Database:** RAII transactions, checked bind calls, blob validation, internal mutex, automatic backup before any schema or format migration.
- **Network:** `127.0.0.1` only, `Host` and `Origin` checks, security headers, `no-store` on API responses, login throttling (5 failures, then 15 s doubling up to 5 min; in memory only, so a restart resets it; never a permanent lockout), 15-minute idle auto-lock.
- **Logs never contain passwords, keys or plaintext.**

## Encryption format and migration

| Version | Meaning |
|---|---|
| 1 | Original format: AES-256-GCM, no AAD |
| 2 | Same cipher, with AAD `"VaultX/record/v2/" + record id` |

Migration rules (nothing happens to your real data unless you opt in):
1. Starting the new version adds a `format_version INTEGER NOT NULL DEFAULT 1` column. This is additive; every existing row is "v1". A backup `vaultx.db.pre-schema-v2-<time>.bak` is written first.
2. v1 records decrypt exactly as before. A v2 record cannot be opened without its AAD and cannot be "downgraded" (the tag covers the AAD).
3. New or edited records are written as v2. Existing ones are not bulk-rewritten automatically.
4. Optional bulk upgrade: `VAULTX_UPGRADE_RECORDS=1` writes a second backup (`...pre-aad-upgrade-<time>.bak`), then upgrades all readable v1 records atomically.
5. Changing the master password re-encrypts everything as v2.

Trade-off: an **older** VaultX build cannot read v2 records. Until a record is upgraded, it is not ID-bound. The master-password verifier keeps the v1 format.

## REST API

All endpoints are under `http://127.0.0.1:18080`. JSON in, JSON out. Item ids are positive integers.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness |
| GET | `/api/status` | `{initialized, unlocked}` |
| POST | `/api/unlock` | `{masterPassword}` (creates the vault on first use) |
| POST | `/api/lock` | Lock and wipe the session |
| POST | `/api/change-password` | `{current, next}` |
| GET / POST | `/api/entries` | List (no secrets) / create |
| GET / PUT / DELETE | `/api/entries/{id}` | Full item / update / delete permanently |
| PATCH | `/api/entries/{id}/favorite` | `{favorite: bool}` |
| PATCH | `/api/entries/{id}/trash` | `{deleted: bool}` |

Errors return `{"error": "..."}` with 400 (invalid input), 401 (locked / wrong password), 403 (forbidden / wrong current password), 404, 409 (conflict), 429 (throttled), 500.

## Known limitations

- `ApiServer` still contains the original detached idle-watcher thread, has no explicit request-size limit and still uses Crow's `<int>` route parameters. The replacement helpers exist (`ApiValidation.h`, `LoginThrottle.*`, `PasswordVault::lockIfIdle`) but are not wired in yet.
- No API integration tests and no CMake/CTest test targets yet.
- Decrypted entries live in `std::string` while unlocked; wiping is best effort. Keys are not locked in RAM (no `mlock` / `VirtualLock`), so the OS may swap them. HTTP and JSON library buffers are outside our control.
- One process should use a vault at a time; the vault caches entries and does not live-sync with other programs.
- Not audited; not a substitute for an established password manager.

## Interview talking points

- **Why AAD?** GCM authenticates ciphertext but not where it is stored. Binding the row id stops an attacker with file access from swapping or cloning records undetected.
- **Why a versioned, opt-in migration?** Cryptographic changes must never make existing data undecryptable, so: additive schema, backup first, atomic upgrade, never delete unreadable rows.
- **Why not keep the master password?** Smaller blast radius: only derived keys live in memory, and a custom allocator wipes every copy. This forced keys for all legacy salts to be derived at unlock.
- **Chicken-and-egg ID problem:** AAD needs the row id, but the id exists only after insert. Solved with `insertSealed()`: reserve the id in a transaction, encrypt with it, finish the row, commit, or roll back everything.
- **Testability through OOP:** the vault depends on `Storage` and `Cipher` interfaces, enabling fast and failure-injecting test doubles.
- **Honest scope:** known gaps are listed above rather than hidden.

## Author

**Harsh Lotiya**
GitHub: [github.com/harsh-1507](https://github.com/harsh-1507)

Never commit `vaultx.db` (it is in `.gitignore`).
