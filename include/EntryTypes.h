#ifndef ENTRYTYPES_H
#define ENTRYTYPES_H

#include <memory>
#include <string>
#include <vector>

#include "Entry.h"

using namespace std;

// Each class below IS-A Entry and customises it by overriding virtual functions.

class LoginEntry : public CloneableEntry<LoginEntry> {
public:
    std::string type() const override { return "Login"; }
    const std::vector<FieldSpec>& specs() const override;
    std::string subtitleKey() const override { return "username"; }
    std::string auditPassword() const override { return field("password"); }
    void validateRules() const override;
};

class SecureNoteEntry : public CloneableEntry<SecureNoteEntry> {
public:
    std::string type() const override { return "Secure Note"; }
    const std::vector<FieldSpec>& specs() const override;
    bool notesRequired() const override { return true; }  // the note IS the content
};

class CardEntry : public CloneableEntry<CardEntry> {
public:
    std::string type() const override { return "Card"; }
    const std::vector<FieldSpec>& specs() const override;
    std::string subtitleKey() const override { return "cardholder"; }
    std::string hint() const override;  // "•••• 1111"
    void validateRules() const override;
};

class IdentityEntry : public CloneableEntry<IdentityEntry> {
public:
    std::string type() const override { return "Identity"; }
    const std::vector<FieldSpec>& specs() const override;
    std::string subtitleKey() const override { return "fullName"; }
    void validateRules() const override;
};

class ApiKeyEntry : public CloneableEntry<ApiKeyEntry> {
public:
    std::string type() const override { return "API Key"; }
    const std::vector<FieldSpec>& specs() const override;
    std::string subtitleKey() const override { return "keyName"; }
    void validateRules() const override;
};

class WifiEntry : public CloneableEntry<WifiEntry> {
public:
    std::string type() const override { return "Wi-Fi"; }
    const std::vector<FieldSpec>& specs() const override;
    std::string subtitleKey() const override { return "ssid"; }
};

// Factory: creates the right concrete class from a type name.
class EntryFactory {
public:
    static std::unique_ptr<Entry> create(const std::string& type);  // throws ApiError(400)
    static std::vector<std::string> types();
};

#endif
