#include "Entry.h"
#include "EntryTypes.h"
#include "Errors.h"
#include "SecureMemory.h"

#include <cctype>
#include <iomanip>
#include <sstream>

using namespace std;

namespace {

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

// For API requests: absent or null = "", text = the text, anything else is an
// error (instead of silently turning a number or object into an empty string).
string getTextStrict(const crow::json::rvalue& obj, const char* key) {
    if (!obj.has(key)) return "";

    auto t = obj[key].t();
    if (t == crow::json::type::Null) return "";
    if (t != crow::json::type::String)
        throw ApiError(400, string("Field must be text: ") + key);

    return string(obj[key].s());
}

bool getBool(const crow::json::rvalue& obj, const char* key) {
    return obj.has(key) && obj[key].t() == crow::json::type::True;
}

}  // namespace

// ------------------------------------------------------------- lifetime
// Decrypted text lives in std::string, which cannot be made self-wiping. This
// overwrites what the entry still holds when it dies (e.g. at lock()). It is
// best effort: copies made earlier by the allocator or by other libraries
// (HTTP buffers, JSON temporaries) are outside our control.
Entry::~Entry() {
    wipe(title_);
    wipe(folder_);
    wipe(notes_);
    for (auto& kv : fields_) wipe(kv.second);
}

// ------------------------------------------------------------- accessors
void Entry::setTitle(const string& value) { title_ = trim(value); }

void Entry::setFolder(const string& value) {
    folder_ = trim(value);
    if (folder_.empty()) folder_ = "Personal";
}

string Entry::field(const string& key) const {
    auto it = fields_.find(key);
    return it == fields_.end() ? "" : it->second;
}

bool Entry::setField(const string& key, const string& value) {
    for (const FieldSpec& spec : specs()) {
        if (spec.key != key) continue;

        // Secrets keep their exact characters; everything else is trimmed.
        string cleaned = spec.secret ? value : trim(value);

        if (cleaned.empty()) fields_.erase(key);
        else fields_[key] = cleaned;

        return true;
    }
    return false;
}

void Entry::restoreField(const string& key, const string& value) {
    fields_[key] = value;
}

string Entry::subtitle() const {
    string key = subtitleKey();
    return key.empty() ? "" : field(key);
}

// ------------------------------------------------------------- validation
void Entry::validate() const {
    if (title_.empty()) throw ApiError(400, "Title is required.");

    if (title_.size() > 120 || hasControlChars(title_))
        throw ApiError(400, "Title is invalid or longer than 120 characters.");

    if (folder_.size() > 60 || hasControlChars(folder_))
        throw ApiError(400, "Folder name is invalid.");

    if (notes_.size() > 5000)
        throw ApiError(400, "Notes are longer than 5000 characters.");

    for (const FieldSpec& spec : specs()) {
        string value = field(spec.key);

        if (value.empty() && spec.required)
            throw ApiError(400, spec.label + " is required.");

        if (value.size() > 2000)
            throw ApiError(400, spec.label + " is too long.");
    }

    if (notesRequired() && trim(notes_).empty())
        throw ApiError(400, "Note content is required.");

    validateRules();  // polymorphic: each type adds its own rules
}

// ------------------------------------------------------------- serialization
string Entry::toPayload() const {
    crow::json::wvalue w;
    w["v"] = 2;
    w["type"] = type();
    w["title"] = title_;
    w["folder"] = folder_;
    w["notes"] = notes_;
    w["favorite"] = favorite_;
    w["deleted"] = deleted_;
    w["created"] = created_;

    crow::json::wvalue f = crow::json::wvalue::object();
    for (const auto& kv : fields_) f[kv.first] = kv.second;
    w["fields"] = std::move(f);

    return w.dump();
}

crow::json::wvalue Entry::toJson(bool full) const {
    crow::json::wvalue w;
    w["id"] = id_;
    w["type"] = type();
    w["title"] = title_;
    w["service"] = title_;      // legacy alias
    w["folder"] = folder_;
    w["category"] = folder_;    // legacy alias
    w["favorite"] = favorite_;
    w["deleted"] = deleted_;
    if (created_ > 0) w["created"] = created_;

    if (full) {
        w["notes"] = notes_;
    } else {
        w["notes"] = "";  // notes can be sensitive: only sent when an item is opened
        w["hasNotes"] = !notes_.empty();
    }

    // Frontend expects these three even when empty.
    w["username"] = "";
    w["password"] = "";
    w["url"] = "";

    if (full) {
        for (const auto& kv : fields_) w[kv.first] = kv.second;
    } else {
        for (const FieldSpec& spec : specs()) {
            auto it = fields_.find(spec.key);
            if (!spec.secret && it != fields_.end()) w[spec.key] = it->second;
        }

        string preview = hint();
        if (!preview.empty()) w["hint"] = preview;
    }

    return w;
}

// ------------------------------------------------------------- factories
unique_ptr<Entry> Entry::fromRequest(const crow::json::rvalue& body) {
    if (body.t() != crow::json::type::Object)
        throw ApiError(400, "Invalid JSON body.");

    string type = getTextStrict(body, "type");
    if (type.empty()) type = "Login";

    unique_ptr<Entry> entry = EntryFactory::create(type);  // throws on unknown type

    entry->setTitle(getTextStrict(body, "title"));
    entry->setFolder(getTextStrict(body, "folder"));
    entry->setNotes(getTextStrict(body, "notes"));

    for (const FieldSpec& spec : entry->specs())
        entry->setField(spec.key, getTextStrict(body, spec.key.c_str()));

    entry->validate();
    return entry;
}

unique_ptr<Entry> Entry::fromPayload(const string& plaintext) {
    if (!plaintext.empty() && plaintext[0] == '{') {
        auto p = crow::json::load(plaintext);
        if (!p || p.t() != crow::json::type::Object)
            throw runtime_error("Corrupt record payload.");

        string type = getString(p, "type");
        if (type.empty()) type = "Login";

        unique_ptr<Entry> entry;
        try {
            entry = EntryFactory::create(type);
        } catch (const ApiError&) {
            throw runtime_error("Unknown record type: " + type);
        }

        entry->setTitle(getString(p, "title"));
        entry->setFolder(getString(p, "folder"));
        entry->setNotes(getString(p, "notes"));
        entry->setFavorite(getBool(p, "favorite"));
        entry->setDeleted(getBool(p, "deleted"));

        if (p.has("created") && p["created"].t() == crow::json::type::Number)
            entry->setCreated(static_cast<long long>(p["created"].i()));

        if (p.has("fields") && p["fields"].t() == crow::json::type::Object)
            for (const auto& kv : p["fields"])
                if (kv.t() == crow::json::type::String)
                    entry->restoreField(kv.key(), string(kv.s()));

        if (entry->title().empty()) throw runtime_error("Corrupt record payload.");
        return entry;
    }

    // Legacy format written by the very first CLI: "service" "username" "password" "category"
    istringstream in(plaintext);
    string service, username, password, category;

    if (!(in >> quoted(service) >> quoted(username) >> quoted(password) >> quoted(category)))
        throw runtime_error("Unrecognised record format.");

    auto login = make_unique<LoginEntry>();
    login->setTitle(service);
    login->setFolder(category);
    login->restoreField("username", username);
    login->restoreField("password", password);
    return login;
}
