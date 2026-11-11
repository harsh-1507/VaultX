#ifndef DATABASELOCATION_H
#define DATABASELOCATION_H

#include <functional>
#include <string>

using namespace std;

// Decides WHERE the vault database lives, in a predictable order:
//
//   1. VAULTX_DB=<path>        explicit path (development, tests, custom setups)
//   2. VAULTX_USE_APPDATA=1    per-user application-data directory:
//                                Windows : %APPDATA%\VaultX\vaultx.db
//                                Linux   : $XDG_DATA_HOME/vaultx/vaultx.db
//                                          (or ~/.local/share/vaultx/vaultx.db)
//                                macOS   : ~/Library/Application Support/VaultX/vaultx.db
//   3. otherwise               ./vaultx.db in the working directory (the
//                              behaviour VaultX has always had)
//
// The default never changes by itself, and existing database files are never
// moved, copied or deleted. If the app-data mode is switched on while an old
// ./vaultx.db exists, the result carries a notice so the user can copy it
// over deliberately.
class DatabaseLocation {
public:
    struct Result {
        string path;    // absolute path of the database file
        string source;  // which rule chose it (for the startup message)
        string notice;  // optional warning, empty if none
    };

    using EnvLookup = function<string(const string& name)>;  // "" when unset

    static Result resolve();                        // uses the real environment
    static Result resolve(const EnvLookup& env);    // injectable, for tests

    // The per-user data directory for the current platform ("" if unknown).
    static string appDataDirectory(const EnvLookup& env);
};

#endif
