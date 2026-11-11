#ifndef ENTRY_H
#define ENTRY_H

#include <map>
#include <string>

#include "crow/json.h"

// One vault item (login, card, identity, note, ...).
// Type-specific values (username, password, url, cardNumber, ...) live in `fields`.
struct Entry {
    int id = 0;
    std::string type = "Login";
    std::string title;
    std::string folder = "Personal";
    std::string notes;
    std::map<std::string, std::string> fields;
    bool favorite = false;
    bool deleted = false;
    long long created = 0;  // ms since epoch, 0 = unknown (legacy record)

    std::string field(const std::string& key) const;

    // Validates and builds an Entry from a request body (throws ApiError 400).
    static Entry fromRequest(const crow::json::rvalue& body);

    // Reads decrypted data: new JSON format or the legacy 4-field format.
    static Entry fromPayload(const std::string& plaintext);

    std::string toPayload() const;        // what gets encrypted
    crow::json::wvalue toJson() const;    // what the frontend receives
};

#endif
