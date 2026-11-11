# 🔐 VaultX

### A Local-First Password & Credential Manager Built with C++17

VaultX is a local, single-user password and credential management application developed using **C++17 and Object-Oriented Programming**.

It provides an encrypted environment to store and manage sensitive information using SQLite and OpenSSL. The application features a browser-based interface powered by a C++ REST API, along with a command-line interface (CLI) that shares the same core vault implementation.

VaultX stores data locally on the user's machine instead of relying on a cloud database.

---

## ✨ Features

- 🔑 **Master Password Authentication** – Initialize and unlock the encrypted vault.
- 🔒 **Encrypted Storage** – Protect credentials using AES-256-GCM authenticated encryption.
- 🗂️ **Multiple Credential Types** – Login, Secure Note, Card, Identity, API Key, and Wi-Fi.
- 📝 **Credential Management** – Create, view, update, and delete entries.
- ⭐ **Organization** – Folders, favourites, trash, and restore functionality.
- 🎲 **Password Generator** – Generate passwords using cryptographically secure randomness.
- 📊 **Password Analyzer** – Analyse password strength and detect password reuse.
- 🔄 **Master Password Change** – Re-encrypt stored credentials when changing the master password.
- 🌐 **Web Interface** – Manage credentials through a browser-based frontend.
- 💻 **CLI Application** – Access the vault through a terminal interface.
- ⏱️ **Automatic Locking** – Lock the vault after 15 minutes of inactivity.

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Programming Language | C++17 |
| Backend | Crow |
| Database | SQLite |
| Cryptographic Library | OpenSSL |
| Encryption | AES-256-GCM |
| Key Derivation | PBKDF2-HMAC-SHA256 |
| Frontend | HTML, CSS, JavaScript |
| Build System | CMake |
| Testing | Custom C++ Test Framework |

---

## 📁 Folder Structure

```text
VaultX/
│
├── include/                         # Header files (15)
│   ├── ApiServer.h
│   ├── ApiValidation.h
│   ├── Crypto.h
│   ├── Database.h
│   ├── DatabaseLocation.h
│   ├── Entry.h
│   ├── EntryTypes.h
│   ├── Errors.h
│   ├── KeyCache.h
│   ├── LoginThrottle.h
│   ├── PasswordAnalyzer.h
│   ├── PasswordGenerator.h
│   ├── PasswordVault.h
│   ├── SecureMemory.h
│   └── Storage.h
│
├── src/                              # Implementation files (12)
│   ├── ApiServer.cpp
│   ├── Crypto.cpp
│   ├── Database.cpp
│   ├── DatabaseLocation.cpp
│   ├── Entry.cpp
│   ├── EntryTypes.cpp
│   ├── LoginThrottle.cpp
│   ├── PasswordAnalyzer.cpp
│   ├── PasswordGenerator.cpp
│   ├── PasswordVault.cpp
│   ├── main.cpp
│   └── server.cpp
│
├── frontend/                         # Web frontend
│   ├── index.html
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
│
├── tests/                            # Automated tests
│   ├── TestFramework.h
│   ├── TestSupport.h
│   ├── test_main.cpp
│   ├── test_crypto.cpp
│   ├── test_database.cpp
│   └── test_vault.cpp
│
├── CMakeLists.txt
├── README.md
└── .gitignore
```

Crow is installed separately inside `third_party/Crow/` during setup.

---

## 📋 Requirements and Installation

### Requirements

| Dependency | Version / Details |
|---|---|
| C++ Compiler | C++17 compatible (GCC 9+) |
| CMake | 3.16 or newer |
| OpenSSL | 3.x development libraries |
| SQLite3 | Development libraries |
| Standalone Asio | Header-only |
| Crow | Header-only web framework |
| Git | For cloning the repository and dependencies |

**Recommended Windows environment:** MSYS2 UCRT64.

### 1. Clone the repository

```bash
git clone https://github.com/harsh-1507/VaultX.git
cd VaultX
```

### 2. Install dependencies

**Windows – MSYS2 UCRT64**

Install [MSYS2](https://www.msys2.org/) and open the MSYS2 UCRT64 terminal.

Update the package database:

```bash
pacman -Syu
```

Install the required packages:

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                   mingw-w64-ucrt-x86_64-cmake \
                   mingw-w64-ucrt-x86_64-ninja \
                   mingw-w64-ucrt-x86_64-openssl \
                   mingw-w64-ucrt-x86_64-sqlite3 \
                   mingw-w64-ucrt-x86_64-asio \
                   git
```

**Linux – Ubuntu / Debian**

```bash
sudo apt update

sudo apt install build-essential cmake libssl-dev \
                 libsqlite3-dev libasio-dev git
```

### 3. Install Crow

From the VaultX project root:

```bash
git clone --depth 1 https://github.com/CrowCpp/Crow.git third_party/Crow
```

After installation, Crow should be available at:

```text
third_party/Crow/include/
```

---

## ⚙️ Build Instructions

### Using CMake (Recommended)

Run these commands from the project root:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

For a Debug build:

```bash
cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

If Ninja is unavailable, use the appropriate generator. For MSYS2 UCRT64:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build --config Release
```

The build generates two applications:

| Executable | Description |
|---|---|
| `vaultx_server.exe` | Web application and REST API |
| `vaultx_cli.exe` | Command-line application |

On Linux, the executables do not have the `.exe` extension.

### Manual Compilation (Windows / MinGW)

If CMake does not work, you can compile the applications directly using GCC.

First, add MSYS2 UCRT64 to your PowerShell PATH:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;" + $env:Path
```

**Compile the Web Server:**

```powershell
g++ -std=c++17 -O2 -Iinclude -Ithird_party/Crow/include src/server.cpp src/Crypto.cpp src/Database.cpp src/DatabaseLocation.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp src/PasswordGenerator.cpp src/ApiServer.cpp -o vaultx_server.exe -lssl -lcrypto -lsqlite3 -lws2_32 -lmswsock
```

**Compile the CLI Application:**

```powershell
g++ -std=c++17 -O2 -Iinclude -Ithird_party/Crow/include src/main.cpp src/Crypto.cpp src/Database.cpp src/DatabaseLocation.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp src/PasswordGenerator.cpp src/ApiServer.cpp -o vaultx_cli.exe -lssl -lcrypto -lsqlite3 -lws2_32 -lmswsock
```

---

## ▶️ Running VaultX

Run the applications from the **VaultX project root directory**.

### 🌐 Web Application

After building with CMake:

```powershell
.\build\vaultx_server.exe
```

If compiled manually:

```powershell
.\vaultx_server.exe
```

Open your browser and navigate to:

**http://127.0.0.1:18080**

### 💻 CLI Application

After building with CMake:

```powershell
.\build\vaultx_cli.exe
```

If compiled manually:

```powershell
.\vaultx_cli.exe
```

### First Launch

On the first launch, create a master password to initialize the vault. On subsequent launches, use the same password to unlock it.

**Important:** The master password is not stored in the database. If you forget it, the encrypted vault data cannot be recovered.

---

## ⚙️ Configuration

VaultX supports environment variables for database location and encryption-format migration.

| Variable | Description |
|---|---|
| `VAULTX_DB` | Specifies an explicit database file path. |
| `VAULTX_USE_APPDATA=1` | Uses the per-user application data directory through the database location resolver. |
| `VAULTX_UPGRADE_RECORDS=1` | Enables bulk migration of legacy encrypted records. |

By default, the database is named `vaultx.db` in the current working directory.

**Example – Specify a custom database path:**

```powershell
$env:VAULTX_DB = "D:\VaultXData\vaultx.db"
.\vaultx_server.exe
```

The explicit `VAULTX_DB` setting takes precedence over the default location.

---

## 🧪 Testing

VaultX includes a lightweight C++ testing framework in the `tests/` directory. Tests use temporary databases instead of the application's actual vault database.

### Compile and Run Tests

Run these commands from the project root.

**1. Crypto Tests**

```powershell
g++ -std=c++17 -O1 -Iinclude -Itests tests/test_main.cpp tests/test_crypto.cpp src/Crypto.cpp -o test_crypto.exe -lssl -lcrypto -lsqlite3

.\test_crypto.exe
```

**2. Database Tests**

```powershell
g++ -std=c++17 -O1 -Iinclude -Itests tests/test_main.cpp tests/test_database.cpp src/Crypto.cpp src/Database.cpp -o test_database.exe -lssl -lcrypto -lsqlite3

.\test_database.exe
```

**3. PasswordVault Tests**

```powershell
g++ -std=c++17 -O1 -Iinclude -Itests tests/test_main.cpp tests/test_vault.cpp src/Crypto.cpp src/Database.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp -o test_vault.exe -lssl -lcrypto -lsqlite3

.\test_vault.exe
```

### Test Coverage

- **Crypto:** Encryption, decryption, incorrect keys, authentication failures, nonce uniqueness, AAD validation, and legacy-format compatibility.
- **Database:** CRUD operations, transactions, persistence, schema migration, backups, and concurrent access.
- **PasswordVault:** Authentication, locking, credential management, password changes, record migration, and key-cache behaviour.

---

## 🏗️ Architecture and OOP Design

VaultX follows a modular object-oriented architecture that separates credential management, encryption, persistence, and HTTP request handling.

### Application Architecture

```text
                  Web Browser
                       |
                       v
                  Crow Server
                       |
                       v
                    ApiServer
                       |
                       v
                  PasswordVault
                    /       \
                   v         v
                Cipher     Storage
                   |         |
                   v         v
                OpenSSL    SQLite
```

The CLI application uses the same `PasswordVault`, `Cipher`, and `Storage` components through a separate entry point.

### Object-Oriented Programming

| Concept | Implementation |
|---|---|
| Abstraction | `Cipher`, `Storage`, and `Entry` abstract interfaces |
| Inheritance | `AesGcmCipher` derives from `Cipher`; `Database` derives from `Storage`; credential classes derive from `Entry` through `CloneableEntry<T>` |
| Polymorphism | Virtual functions and `unique_ptr<Entry>` for credential types |
| Encapsulation | Private state and controlled operations in `PasswordVault`, `Database`, and `KeyCache` |

### Design Patterns

| Pattern | Implementation |
|---|---|
| Factory | `EntryFactory` |
| Template Method | `Cipher::encrypt()` |
| CRTP | `CloneableEntry<T>` |
| Prototype | `Entry::clone()` |
| RAII | SQLite statements and transactions, OpenSSL contexts, and secure-memory helpers |

---

## 🔒 Security and Encryption

### Encryption

- AES-256-GCM authenticated encryption.
- Fresh random 96-bit nonce for every encryption operation.
- PBKDF2-HMAC-SHA256 key derivation.
- 600,000 PBKDF2 iterations.
- Random 16-byte salt.

### Master Password Protection

The master password is not stored in the database. It is used for vault initialization, unlocking, and password changes. The unlocked session retains derived keys rather than the original master password.

### Secure Memory

- Sensitive binary buffers use memory-cleansing mechanisms.
- Cached keys are cleansed when evicted or when the vault is locked.
- Temporary sensitive buffers are cleared on destruction on a best-effort basis.

### Authenticated Record Binding

Version-2 encrypted records use AES-GCM Additional Authenticated Data (AAD) to bind ciphertext to its database record ID. This helps prevent encrypted records from being swapped or copied without detection.

### Database Protection

- Transaction-based database operations.
- Atomic vault-wide re-encryption during master password changes.
- Backups before encryption-format migrations.
- Legacy encrypted records supported through versioned migration.

### Local Server Protection

- Server binds to `127.0.0.1`.
- Host and Origin validation.
- Security-related response headers.
- `no-store` on API responses.
- Automatic vault locking after inactivity.

---

## 🌐 REST API

The Crow backend exposes a local REST API at:

```text
http://127.0.0.1:18080
```

Requests and responses use JSON.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Check server availability |
| GET | `/api/status` | Check vault initialization and unlock status |
| POST | `/api/unlock` | Initialize or unlock the vault |
| POST | `/api/lock` | Lock the vault |
| POST | `/api/change-password` | Change the master password |
| GET | `/api/entries` | List credential entries |
| POST | `/api/entries` | Create a credential entry |
| GET | `/api/entries/{id}` | Retrieve a credential |
| PUT | `/api/entries/{id}` | Update a credential |
| DELETE | `/api/entries/{id}` | Permanently delete a credential |
| PATCH | `/api/entries/{id}/favorite` | Update favourite status |
| PATCH | `/api/entries/{id}/trash` | Update trash status |

---

## 👨‍💻 Author

**Harsh Lotiya**

- GitHub: [harsh-1507](https://github.com/harsh-1507)
- Repository: [VaultX](https://github.com/harsh-1507/VaultX)

---
