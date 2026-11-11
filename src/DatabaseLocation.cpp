#include "DatabaseLocation.h"

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <system_error>

using namespace std;

namespace {

string realEnv(const string& name) {
    const char* value = getenv(name.c_str());
    return value ? string(value) : string();
}

string absolutePath(const filesystem::path& p) {
    error_code ec;
    filesystem::path abs = filesystem::absolute(p, ec);
    return (ec ? p : abs).lexically_normal().string();
}

}  // namespace

string DatabaseLocation::appDataDirectory(const EnvLookup& env) {
#ifdef _WIN32
    string base = env("APPDATA");
    return base.empty() ? string() : (filesystem::path(base) / "VaultX").string();
#elif defined(__APPLE__)
    string home = env("HOME");
    return home.empty() ? string()
                        : (filesystem::path(home) / "Library" / "Application Support" / "VaultX")
                              .string();
#else
    string xdg = env("XDG_DATA_HOME");
    if (!xdg.empty()) return (filesystem::path(xdg) / "vaultx").string();

    string home = env("HOME");
    return home.empty() ? string()
                        : (filesystem::path(home) / ".local" / "share" / "vaultx").string();
#endif
}

DatabaseLocation::Result DatabaseLocation::resolve() { return resolve(realEnv); }

DatabaseLocation::Result DatabaseLocation::resolve(const EnvLookup& env) {
    Result result;

    // 1. Explicit path always wins.
    string explicitPath = env("VAULTX_DB");
    if (!explicitPath.empty()) {
        result.path = explicitPath == ":memory:" ? explicitPath : absolutePath(explicitPath);
        result.source = "VAULTX_DB";
        return result;
    }

    // 2. Opt-in per-user application-data directory.
    if (env("VAULTX_USE_APPDATA") == "1") {
        string directory = appDataDirectory(env);
        if (directory.empty())
            throw runtime_error(
                "VAULTX_USE_APPDATA=1 is set but the application-data directory "
                "could not be determined.");

        error_code ec;
        filesystem::create_directories(directory, ec);
        if (ec)
            throw runtime_error("Could not create data directory '" + directory +
                                "': " + ec.message());

        result.path = absolutePath(filesystem::path(directory) / "vaultx.db");
        result.source = "application-data directory";

        error_code existsEc;
        if (!filesystem::exists(result.path, existsEc) &&
            filesystem::exists("vaultx.db", existsEc))
            result.notice =
                "An existing database was found at '" + absolutePath("vaultx.db") +
                "' but it was NOT moved. To keep using it, unset VAULTX_USE_APPDATA; "
                "to move it, copy the file to '" + result.path + "' yourself.";

        return result;
    }

    // 3. Historical default: next to wherever VaultX is started.
    result.path = absolutePath("vaultx.db");
    result.source = "working directory (default)";
    return result;
}
