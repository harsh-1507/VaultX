#ifndef ENTRY_H
#define ENTRY_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "crow/json.h"

using namespace std;

// Describes one input field of an entry type.
struct FieldSpec {
    std::string key;
    std::string label;
    bool required;
    bool secret;
};

// Abstract base class of everything stored in the vault.
//
// Concrete types (LoginEntry, CardEntry, ...) implement the pure virtual
// functions and may override the others. Code that works with a vault item
// only ever talks to Entry, so a new type is added by writing one class.
class Entry {
public:
    Entry() = default;
    Entry(const Entry&) = default;
    Entry& operator=(const Entry&) = default;
    virtual ~Entry();  // overwrites the decrypted text (best effort), see Entry.cpp

    // ---- every concrete type must provide these ----
    virtual std::string type() const = 0;
    virtual const std::vector<FieldSpec>& specs() const = 0;
    virtual std::unique_ptr<Entry> clone() const = 0;

    // ---- behaviour a concrete type may override ----
    virtual std::string subtitleKey() const { return ""; }    // field shown under the title
    virtual std::string auditPassword() const { return ""; }  // password to strength-check
    virtual std::string hint() const { return ""; }           // safe preview (e.g. card last 4)
    virtual bool notesRequired() const { return false; }
    virtual void validateRules() const {}                     // type-specific validation

    // ---- shared state and behaviour ----
    int id() const { return id_; }
    const std::string& title() const { return title_; }
    const std::string& folder() const { return folder_; }
    const std::string& notes() const { return notes_; }
    bool favorite() const { return favorite_; }
    bool deleted() const { return deleted_; }
    long long created() const { return created_; }
    const std::map<std::string, std::string>& fields() const { return fields_; }

    void setId(int value) { id_ = value; }
    void setTitle(const std::string& value);
    void setFolder(const std::string& value);
    void setNotes(const std::string& value) { notes_ = value; }
    void setFavorite(bool value) { favorite_ = value; }
    void setDeleted(bool value) { deleted_ = value; }
    void setCreated(long long value) { created_ = value; }

    std::string field(const std::string& key) const;
    bool setField(const std::string& key, const std::string& value);      // only known keys
    void restoreField(const std::string& key, const std::string& value);  // loading from disk
    std::string subtitle() const;

    void validate() const;  // throws ApiError(400); calls validateRules()

    std::string toPayload() const;                    // what gets encrypted
    crow::json::wvalue toJson(bool full = true) const;  // `full` = false hides secrets/notes

    static std::unique_ptr<Entry> fromRequest(const crow::json::rvalue& body);
    static std::unique_ptr<Entry> fromPayload(const std::string& plaintext);

protected:
    int id_ = 0;
    std::string title_;
    std::string folder_ = "Personal";
    std::string notes_;
    std::map<std::string, std::string> fields_;
    bool favorite_ = false;
    bool deleted_ = false;
    long long created_ = 0;  // ms since epoch, 0 = unknown (legacy record)
};

// Helper base that implements clone() once for every concrete type (CRTP).
template <class Derived>
class CloneableEntry : public Entry {
public:
    std::unique_ptr<Entry> clone() const override {
        return std::make_unique<Derived>(static_cast<const Derived&>(*this));
    }
};

#endif
