#include "EntryTypes.h"
#include "Errors.h"

#include <cctype>
#include <functional>
#include <map>

using namespace std;

namespace {

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
    if (v.find('/') != 2) return false;

    string mm = v.substr(0, 2), yy = v.substr(3);
    if (!allDigits(mm, 2, 2) || !(yy.size() == 2 || yy.size() == 4) || !allDigits(yy, 2, 4))
        return false;

    int month = stoi(mm);
    return month >= 1 && month <= 12;
}

void requireUrl(const string& value) {
    if (!value.empty() && value.rfind("http://", 0) != 0 && value.rfind("https://", 0) != 0)
        throw ApiError(400, "URLs must start with http:// or https://.");
}

}  // namespace

// ------------------------------------------------------------------ Login
const vector<FieldSpec>& LoginEntry::specs() const {
    static const vector<FieldSpec> s = {
        {"username", "Username", true, false},
        {"password", "Password", true, true},
        {"url", "Website URL", false, false}};
    return s;
}

void LoginEntry::validateRules() const {
    if (field("password").size() < 6)
        throw ApiError(400, "Password must contain at least 6 characters.");
    requireUrl(field("url"));
}

// ------------------------------------------------------------------ Secure note
const vector<FieldSpec>& SecureNoteEntry::specs() const {
    static const vector<FieldSpec> s;  // no extra fields: the note text is the content
    return s;
}

// ------------------------------------------------------------------ Card
const vector<FieldSpec>& CardEntry::specs() const {
    static const vector<FieldSpec> s = {
        {"cardholder", "Cardholder name", true, false},
        {"number", "Card number", true, true},
        {"expiry", "Expiry date", true, false},
        {"cvv", "CVV", false, true},
        {"pin", "PIN", false, true}};
    return s;
}

string CardEntry::hint() const {
    string digits = stripSeparators(field("number"));
    if (digits.size() < 4) return "";
    return string("\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2 ") +
           digits.substr(digits.size() - 4);
}

void CardEntry::validateRules() const {
    if (!allDigits(stripSeparators(field("number")), 12, 19))
        throw ApiError(400, "Card number must contain 12 to 19 digits.");
    if (!validExpiry(field("expiry")))
        throw ApiError(400, "Expiry date must look like MM/YY.");
    if (!field("cvv").empty() && !allDigits(field("cvv"), 3, 4))
        throw ApiError(400, "CVV must be 3 or 4 digits.");
    if (!field("pin").empty() && !allDigits(field("pin"), 4, 12))
        throw ApiError(400, "PIN must be 4 to 12 digits.");
}

// ------------------------------------------------------------------ Identity
const vector<FieldSpec>& IdentityEntry::specs() const {
    static const vector<FieldSpec> s = {
        {"fullName", "Full name", true, false},
        {"email", "Email", false, false},
        {"phone", "Phone", false, false},
        {"address", "Address", false, false},
        {"idNumber", "ID number", false, true}};
    return s;
}

void IdentityEntry::validateRules() const {
    string mail = field("email");
    if (mail.empty()) return;

    size_t at = mail.find('@');
    if (at == string::npos || at == 0 || mail.find('.', at) == string::npos)
        throw ApiError(400, "Email address looks invalid.");
}

// ------------------------------------------------------------------ API key
const vector<FieldSpec>& ApiKeyEntry::specs() const {
    static const vector<FieldSpec> s = {
        {"keyName", "Key name", true, false},
        {"apiKey", "API key", true, true},
        {"endpoint", "Endpoint URL", false, false}};
    return s;
}

void ApiKeyEntry::validateRules() const { requireUrl(field("endpoint")); }

// ------------------------------------------------------------------ Wi-Fi
const vector<FieldSpec>& WifiEntry::specs() const {
    static const vector<FieldSpec> s = {
        {"ssid", "Network name (SSID)", true, false},
        {"password", "Password", true, true},
        {"security", "Security type", false, false}};
    return s;
}

// ------------------------------------------------------------------ Factory
unique_ptr<Entry> EntryFactory::create(const string& type) {
    static const map<string, function<unique_ptr<Entry>()>> registry = {
        {"Login", [] { return make_unique<LoginEntry>(); }},
        {"Secure Note", [] { return make_unique<SecureNoteEntry>(); }},
        {"Card", [] { return make_unique<CardEntry>(); }},
        {"Identity", [] { return make_unique<IdentityEntry>(); }},
        {"API Key", [] { return make_unique<ApiKeyEntry>(); }},
        {"Wi-Fi", [] { return make_unique<WifiEntry>(); }}};

    auto it = registry.find(type);
    if (it == registry.end()) throw ApiError(400, "Unknown item type.");
    return it->second();
}

vector<string> EntryFactory::types() {
    return {"Login", "Secure Note", "Card", "Identity", "API Key", "Wi-Fi"};
}
