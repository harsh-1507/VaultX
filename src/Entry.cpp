#include "Entry.h"
#include "Errors.h"

#include <cctype>
#include <iomanip>
#include <vector>
#include <sstream>

using namespace std;

namespace {

struct Spec {
    const char* key;
    const char* label;
    bool required;
};

// Fields each record type is allowed to hold (anything else is dropped).
const map<string, vector<Spec>> SCHEMA = {
    {"Login", {{"username", "Username", true},
               {"password", "Password", true},
               {"url", "Website URL", false}}},
    {"Secure Note", {}},
    {"Card", {{"cardholder", "Cardholder name", true},
              {"number", "Card number", true},
              {"expiry", "Expiry date", true},
              {"cvv", "CVV", false},
              {"pin", "PIN", false}}},
    {"Identity", {{"fullName", "Full name", true},
                  {"email", "Email", false},
                  {"phone", "Phone", false},
                  {"address", "Address", false},
                  {"idNumber", "ID number", false}}},
    {"API Key", {{"keyName", "Key name", true},
                 {"apiKey", "API key", true},
                 {"endpoint", "Endpoint URL", false}}},
    {"Wi-Fi", {{"ssid", "Network name (SSID)", true},
               {"password", "Password", true},
               {"security", "Security type", false}}}};

bool allDigits(const string& s, size_t minLen, size_t maxLen) {
    if (s.size() < minLen || s.size() > maxLen) return false;
    for (unsigned char c : s)
        if (!isdigit(c)) return false;
    return true;
}

string stripSeparators(const string& s) {
    string out;
    for (char c : s)
        if (c != ' ' && c != '-') out += c;
    return out;
}

bool validExpiry(const string& raw) {
    string v = stripSeparators(raw);
    size_t slash = v.find('/');
    if (slash != 2) return false;
    string mm = v.substr(0, 2), yy = v.substr(3);
    if (!allDigits(mm, 2, 2) || !(yy.size() == 2 || yy.size() == 4) || !allDigits(yy, 2, 4))
        return false;
    int month = stoi(mm);
    return month >= 1 && month <= 12;
}

bool validUrl(const string& v) {
    return v.rfind("http://", 0) == 0 || v.rfind("https://", 0) == 0;
}

void validateTypeRules(const Entry& e) {
    if (e.type == "Login" && e.field("password").size() < 6)
        throw ApiError(400, "Password must contain at least 6 characters.");

    if (e.type == "Card") {
        string digits = stripSeparators(e.field("number"));
        if (!allDigits(digits, 12, 19))
            throw ApiError(400, "Card number must contain 12 to 19 digits.");
        if (!validExpiry(e.field("expiry")))
            throw ApiError(400, "Expiry date must look like MM/YY.");
        if (!e.field("cvv").empty() && !allDigits(e.field("cvv"), 3, 4))
            throw ApiError(400, "CVV must be 3 or 4 digits.");
        if (!e.field("pin").empty() && !allDigits(e.field("pin"), 4, 12))
            throw ApiError(400, "PIN must be 4 to 12 digits.");
    }

    if (e.type == "Identity" && !e.field("email").empty()) {
        string m = e.field("email");
        size_t at = m.find('@');
        if (at == string::npos || at == 0 || m.find('.', at) == string::npos)
            throw ApiError(400, "Email address looks invalid.");
    }

    for (const char* key : {"url", "endpoint"})
        if (!e.field(key).empty() && !validUrl(e.field(key)))
            throw ApiError(400, "URLs must start with http:// or https://.");

    if (e.type == "Secure Note") {
        string n = e.notes;
        if (n.find_first_not_of(" \t\r\n") == string::npos)
            throw ApiError(400, "Note content is required.");
    }
}

string trim(const string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

bool hasControlChars(const string& s) {
    for (unsigned char c : s)
        if (c < 0x20) return true;
    return false;
}

string getString(const crow::json::rvalue& obj, const char* key) {
    if (!obj.has(key) || obj[key].t() != crow::json::type::String) return "";
    return string(obj[key].s());
}

bool getBool(const crow::json::rvalue& obj, const char* key) {
    return obj.has(key) && obj[key].t() == crow::json::type::True;
}

}  // namespace

string Entry::field(const string& key) const {
    auto it = fields.find(key);
    return it == fields.end() ? "" : it->second;
}

Entry Entry::fromRequest(const crow::json::rvalue& body) {
    if (body.t() != crow::json::type::Object)
        throw ApiError(400, "Invalid JSON body.");

    Entry e;

    e.type = getString(body, "type");
    if (e.type.empty()) e.type = "Login";

    auto schema = SCHEMA.find(e.type);
    if (schema == SCHEMA.end()) throw ApiError(400, "Unknown item type.");

    e.title = trim(getString(body, "title"));
    if (e.title.empty()) throw ApiError(400, "Title is required.");
    if (e.title.size() > 120 || hasControlChars(e.title))
        throw ApiError(400, "Title is invalid or longer than 120 characters.");

    e.folder = trim(getString(body, "folder"));
    if (e.folder.empty()) e.folder = "Personal";
    if (e.folder.size() > 60 || hasControlChars(e.folder))
        throw ApiError(400, "Folder name is invalid.");

    e.notes = getString(body, "notes");
    if (e.notes.size() > 5000)
        throw ApiError(400, "Notes are longer than 5000 characters.");

    for (const Spec& spec : schema->second) {
        string key = spec.key;
        string value = getString(body, spec.key);

        // Secrets keep their exact characters; everything else is trimmed.
        bool secret = key == "password" || key == "apiKey" || key == "pin" || key == "cvv";
        if (!secret) value = trim(value);

        if (value.empty()) {
            if (spec.required) throw ApiError(400, string(spec.label) + " is required.");
            continue;
        }
        if (value.size() > 2000)
            throw ApiError(400, string(spec.label) + " is too long.");

        e.fields[key] = value;
    }

    validateTypeRules(e);
    return e;
}

Entry Entry::fromPayload(const string& plaintext) {
    Entry e;

    if (!plaintext.empty() && plaintext[0] == '{') {
        auto p = crow::json::load(plaintext);
        if (!p || p.t() != crow::json::type::Object)
            throw runtime_error("Corrupt record payload.");

        e.type = getString(p, "type");
        e.title = getString(p, "title");
        e.folder = getString(p, "folder");
        e.notes = getString(p, "notes");
        e.favorite = getBool(p, "favorite");
        e.deleted = getBool(p, "deleted");
        if (p.has("created") && p["created"].t() == crow::json::type::Number)
            e.created = static_cast<long long>(p["created"].i());

        if (p.has("fields") && p["fields"].t() == crow::json::type::Object)
            for (const auto& kv : p["fields"])
                if (kv.t() == crow::json::type::String)
                    e.fields[kv.key()] = string(kv.s());

        if (e.title.empty()) throw runtime_error("Corrupt record payload.");
        return e;
    }

    // Legacy format written by the CLI: "service" "username" "password" "category"
    istringstream in(plaintext);
    string service, username, password, category;
    if (!(in >> quoted(service) >> quoted(username) >> quoted(password) >> quoted(category)))
        throw runtime_error("Unrecognised record format.");

    e.type = "Login";
    e.title = service;
    e.folder = category.empty() ? "Personal" : category;
    e.fields["username"] = username;
    e.fields["password"] = password;
    return e;
}

string Entry::toPayload() const {
    crow::json::wvalue w;
    w["v"] = 2;
    w["type"] = type;
    w["title"] = title;
    w["folder"] = folder;
    w["notes"] = notes;
    w["favorite"] = favorite;
    w["deleted"] = deleted;
    w["created"] = created;

    crow::json::wvalue f = crow::json::wvalue::object();
    for (const auto& kv : fields) f[kv.first] = kv.second;
    w["fields"] = std::move(f);

    return w.dump();
}

crow::json::wvalue Entry::toJson() const {
    crow::json::wvalue w;
    w["id"] = id;
    w["type"] = type;
    w["title"] = title;
    w["service"] = title;      // legacy alias
    w["folder"] = folder;
    w["category"] = folder;    // legacy alias
    w["notes"] = notes;
    w["favorite"] = favorite;
    w["deleted"] = deleted;
    if (created > 0) w["created"] = created;

    // Frontend expects these three even when empty.
    w["username"] = "";
    w["password"] = "";
    w["url"] = "";
    for (const auto& kv : fields) w[kv.first] = kv.second;

    return w;
}
