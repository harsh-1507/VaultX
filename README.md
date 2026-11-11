# VaultX 🔐
### Local-First Encrypted Password & Credential Manager

**VaultX** is a password and credential manager built using **C++17, Object-Oriented Programming, Crow, SQLite and OpenSSL**.

It provides a local vault for managing sensitive information through a modern web interface, with a separate console application also available.

The project focuses on modular C++ architecture, object-oriented design, database management, REST API development and applied cryptography.

> **Local-first by design:** VaultX runs on your own machine and stores its database locally. It does not require a cloud account or a hosted database.

---

## ✨ Features

### 🔐 Vault Management
- Master password-based vault initialization and authentication.
- Lock and unlock functionality.
- Automatic vault locking after inactivity.
- Login attempt throttling.
- Master password change functionality.

### 🗂️ Credential Management
Supports six types of credentials:

- Login credentials
- Secure notes
- Credit/debit cards
- Identity information
- API keys
- Wi-Fi credentials

Additional functionality:
- Create, view, edit and delete entries.
- Mark entries as favorites.
- Move entries to Trash.
- Restore or permanently delete trashed entries.
- Organize and manage saved credentials.

### 🛠️ Password Tools
- Password generation.
- Password strength analysis.
- Credential-specific validation.

### 🖥️ User Interface
- Modern dark-themed interface.
- Dashboard for managing credentials.
- Search and category-based organization.
- Favorites and Trash sections.
- Interactive entry management.

---

## 🛠️ Tech Stack

| Technology | Usage |
|---|---|
| **C++17** | Backend logic and OOP architecture |
| **Crow** | HTTP server and REST APIs |
| **SQLite** | Local persistent storage |
| **OpenSSL** | Encryption and cryptographic operations |
| **HTML5** | Frontend structure |
| **CSS3** | Styling and layout |
| **JavaScript** | Frontend functionality and API communication |
| **CMake** | Build system |

---

## 🏗️ System Architecture

VaultX uses a modular architecture that separates frontend interactions, API handling, vault operations, cryptographic functionality and persistent storage.

```text
             ┌─────────────────────────┐
             │      Web Frontend       │
             │     HTML / CSS / JS     │
             └────────────┬────────────┘
                          │
                       HTTP/JSON
                          │
                          ▼
             ┌─────────────────────────┐
             │       Crow Server      │
             │       REST API         │
             └────────────┬────────────┘
                          │
                          ▼
             ┌─────────────────────────┐
             │      PasswordVault     │
             │     Vault Operations   │
             └────────────┬────────────┘
                          │
                 ┌────────┴────────┐
                 │                 │
                 ▼                 ▼
        ┌────────────────┐  ┌────────────────┐
        │  Crypto Module │  │ Database Layer │
        │    OpenSSL     │  │     SQLite     │
        └────────────────┘  └────────────────┘
```

### Application Flow

1. The user interacts with the frontend.
2. The frontend communicates with the local Crow server through HTTP requests.
3. The API server handles requests and coordinates vault operations.
4. `PasswordVault` manages credential operations through abstract interfaces.
5. The cryptographic module encrypts and decrypts sensitive data.
6. SQLite provides persistent local storage.

VaultX also includes a console application that uses the same core backend components without the web interface.

---

## 🧩 Object-Oriented Design

A central objective of VaultX is applying OOP concepts to a practical C++ application.

| OOP Concept | Implementation |
|---|---|
| **Abstraction** | `Cipher`, `Storage` and `Entry` interfaces |
| **Inheritance** | Specialized credential classes inherit from common abstractions |
| **Polymorphism** | Virtual functions and `unique_ptr<Entry>` for handling different entry types |
| **Encapsulation** | Internal state managed by dedicated classes |
| **Factory Pattern** | `EntryFactory` creates appropriate credential types |
| **Template Method** | Common encryption workflow in the `Cipher` abstraction |
| **CRTP** | `CloneableEntry` for reusable cloning behavior |
| **Prototype Pattern** | Credential objects support polymorphic cloning |
| **RAII** | SQLite statements and OpenSSL contexts use resource-management techniques |

### Core Components

| Class / Component | Responsibility |
|---|---|
| `Entry` | Abstract representation of a credential |
| `LoginEntry` | Login credential representation |
| `SecureNoteEntry` | Secure note representation |
| `CardEntry` | Card information |
| `IdentityEntry` | Identity information |
| `ApiKeyEntry` | API key information |
| `WifiEntry` | Wi-Fi credentials |
| `EntryFactory` | Creates credential objects |
| `Storage` | Abstract storage interface |
| `Database` | SQLite storage implementation |
| `Cipher` | Abstract cryptographic interface |
| `AesGcmCipher` | AES-GCM cryptographic implementation |
| `PasswordVault` | Coordinates vault operations |
| `KeyCache` | Manages cached key-related data |
| `ApiServer` | Handles HTTP requests |
| `PasswordGenerator` | Generates passwords |
| `PasswordAnalyzer` | Analyzes password strength |

Adding another credential type can be done by introducing a new entry subclass and registering it with the factory.

---

## 🔒 Security Architecture

VaultX uses cryptographic techniques to protect stored credentials.

### 1. Key Derivation

The master password is processed using:

**PBKDF2-HMAC-SHA256**

- 600,000 iterations.
- Random salt.
- 256-bit derived key.

This makes password-based key derivation more computationally expensive and helps protect against rapid offline password guessing.

### 2. Authenticated Encryption

VaultX uses:

**AES-256-GCM**

Important properties:

- 256-bit encryption key.
- Fresh random nonce for each encryption operation.
- Authentication tag for integrity verification.
- Decryption verifies authenticity before accepting the plaintext.

### 3. Credential Storage

- Sensitive credential information is encrypted before database storage.
- Entry lists are designed to return metadata rather than expose credential secrets.
- Full credential information is retrieved when an entry is opened.
- Master password changes re-encrypt the vault within a database transaction.

### 4. Additional Protections

- Master password verification.
- Unlock attempt throttling.
- Automatic vault locking.
- Localhost-only server binding.
- Host and Origin checks.
- Sensitive key cleanup when locking the vault.

> **Security disclaimer:** VaultX is an educational and portfolio project. It has not undergone an independent security audit and should not be considered a production-certified password manager.

---

## 🗄️ Database Design

VaultX uses SQLite for persistent local storage.

The main tables are:

### `password_entries`

Stores encrypted credential records and their associated metadata.

| Column | Purpose |
|---|---|
| `id` | Credential identifier |
| `salt` | Encryption-related salt |
| `nonce` | Encryption nonce |
| `ciphertext` | Encrypted credential data |
| `auth_tag` | GCM authentication tag |
| `favorite` | Favorite status |
| `deleted` | Trash status |

### `vault_metadata`

Stores vault-level information required for initialization and master password verification.

Database migrations are used to evolve the schema without requiring users to delete their existing database.

---

## 📁 Project Structure

```text
VaultX/
│
├── include/
│   ├── ApiServer.h
│   ├── Crypto.h
│   ├── Database.h
│   ├── Entry.h
│   ├── EntryTypes.h
│   ├── Errors.h
│   ├── KeyCache.h
│   ├── PasswordAnalyzer.h
│   ├── PasswordGenerator.h
│   ├── PasswordVault.h
│   └── Storage.h
│
├── src/
│   ├── ApiServer.cpp
│   ├── Crypto.cpp
│   ├── Database.cpp
│   ├── Entry.cpp
│   ├── EntryTypes.cpp
│   ├── PasswordAnalyzer.cpp
│   ├── PasswordGenerator.cpp
│   ├── PasswordVault.cpp
│   ├── main.cpp
│   └── server.cpp
│
├── frontend/
│   ├── index.html
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
│
├── third_party/
│   └── Crow/
│
├── CMakeLists.txt
├── README.md
└── .gitignore
```

---

## ⚙️ Installation & Setup

### Prerequisites

Make sure you have:

- C++17-compatible compiler.
- GCC / MinGW or MSVC.
- CMake (recommended).
- OpenSSL development libraries.
- SQLite3 development libraries.
- Standalone Asio headers.
- Crow headers.

**Important:** The source ZIP does not include the Crow dependency. Place the Crow headers inside `third_party/Crow/` before building.

### 1. Clone the repository

Open PowerShell:

```powershell
git clone https://github.com/harsh-1507/VaultX.git
cd VaultX
```

If your repository uses a different capitalization or name, adjust the URL accordingly.

### 2. Build using CMake (Recommended)

Configure the project:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
```

Build both applications:

```powershell
cmake --build build --config Release
```

### 3. Run the Web Application

```powershell
.\build\vaultx_server.exe
```

Open the following address in your browser:

```text
http://127.0.0.1:18080
```

### 4. Run the Console Application

Open another PowerShell terminal in the project directory:

```powershell
.\build\vaultx_cli.exe
```

Both applications use the same core components and local database.

---

## 🪟 Manual Build Using PowerShell (Without CMake)

If CMake is unavailable or the CMake build fails, you can compile the project directly using GCC.

**Requirements:** GCC, Crow, Asio, SQLite3 and OpenSSL must already be installed and accessible to the compiler.

Run these commands from the **VaultX project root directory**.

### 1. Compile the Web Server

```powershell
g++ -std=c++17 -O2 -Iinclude -Ithird_party/Crow/include src/server.cpp src/Crypto.cpp src/Database.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp src/PasswordGenerator.cpp src/ApiServer.cpp -o vaultx_server.exe -lssl -lcrypto -lsqlite3 -lws2_32 -lmswsock
```

### 2. Run the Web Server

```powershell
.\vaultx_server.exe
```

Open:

```text
http://127.0.0.1:18080
```

### 3. Compile the Console Application

```powershell
g++ -std=c++17 -O2 -Iinclude -Ithird_party/Crow/include src/main.cpp src/Crypto.cpp src/Database.cpp src/Entry.cpp src/EntryTypes.cpp src/PasswordVault.cpp src/PasswordAnalyzer.cpp src/PasswordGenerator.cpp src/ApiServer.cpp -o vaultx_cli.exe -lssl -lcrypto -lsqlite3 -lws2_32 -lmswsock
```

### 4. Run the Console Application

```powershell
.\vaultx_cli.exe
```

### Troubleshooting

| Error | What to check |
|---|---|
| `g++ is not recognized` | Install GCC and add its `bin` directory to PATH |
| `cmake is not recognized` | Install CMake or use the manual GCC commands |
| `crow.h: No such file` | Check `third_party/Crow/include` |
| `asio.hpp: No such file` | Install standalone Asio and configure its include path |
| `sqlite3.h: No such file` | Install SQLite development headers |
| `openssl/evp.h: No such file` | Install OpenSSL development headers |
| `cannot find -lcrypto` | Configure the OpenSSL library path |
| `cannot find -lsqlite3` | Configure the SQLite library path |

**Note:** The manual commands assume your compiler can already locate the required headers and libraries. Installing a dependency alone does not necessarily add its paths to GCC.

---

## 🎯 Learning Outcomes

VaultX was built to explore practical applications of:

- Modern C++ and object-oriented programming.
- Abstraction, inheritance and polymorphism.
- Design patterns and resource management.
- REST API development using Crow.
- Relational database management with SQLite.
- Applied cryptography using OpenSSL.
- Frontend and backend integration.
- Modular software architecture.

---

## 👨‍💻 Author

**Harsh Lotiya**

- GitHub: [harsh-1507](https://github.com/harsh-1507)

---

