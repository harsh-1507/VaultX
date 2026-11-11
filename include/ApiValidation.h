#ifndef APIVALIDATION_H
#define APIVALIDATION_H

#include <cctype>
#include <climits>
#include <string>

#include "Errors.h"

using namespace std;

// Small, dependency-free request checks used by ApiServer (and unit-tested
// without needing a running web server).
namespace ApiValidation {

constexpr size_t MAX_BODY_BYTES = 64 * 1024;  // largest accepted JSON request body
constexpr int MAX_JSON_DEPTH = 16;            // deepest accepted JSON nesting

// Entry id from a URL segment: 1..INT_MAX, digits only (no sign, no spaces,
// no leading zeros trouble such as "0x10"). Throws ApiError(400) otherwise.
inline int parseEntryId(const string& text) {
    if (text.empty() || text.size() > 10) throw ApiError(400, "Invalid item id.");

    long long value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') throw ApiError(400, "Invalid item id.");
        value = value * 10 + (c - '0');
    }

    if (value < 1 || value > INT_MAX) throw ApiError(400, "Invalid item id.");
    return static_cast<int>(value);
}

// True if the JSON text nests arrays/objects no deeper than maxDepth.
// Strings (including escaped quotes) are skipped. Run it BEFORE the parser so
// a hostile "[[[[[..." body cannot exhaust the stack.
inline bool jsonDepthOk(const string& text, int maxDepth = MAX_JSON_DEPTH) {
    int depth = 0;
    bool inString = false, escaped = false;

    for (char c : text) {
        if (inString) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') inString = false;
            continue;
        }

        if (c == '"') inString = true;
        else if (c == '{' || c == '[') { if (++depth > maxDepth) return false; }
        else if (c == '}' || c == ']') { if (depth > 0) depth--; }
    }
    return true;
}

// Static file names: letters, digits, '-', '_' and a single '.', must end in
// `extension` (".css" / ".js"), never start with '.', no "..", at most 64 chars.
inline bool safeStaticName(const string& name, const string& extension) {
    if (name.empty() || name.size() > 64 || name[0] == '.' ||
        name.find("..") != string::npos)
        return false;

    for (unsigned char c : name) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        if (!ok) return false;
    }

    return name.size() > extension.size() &&
           name.compare(name.size() - extension.size(), extension.size(), extension) == 0;
}

// True if a Content-Type header value is JSON (parameters like charset are fine).
inline bool isJsonContentType(const string& value) {
    static const string json = "application/json";
    if (value.size() < json.size()) return false;

    for (size_t i = 0; i < json.size(); i++)
        if (tolower(static_cast<unsigned char>(value[i])) != json[i]) return false;

    return value.size() == json.size() || value[json.size()] == ';' ||
           value[json.size()] == ' ';
}

}  // namespace ApiValidation

#endif
