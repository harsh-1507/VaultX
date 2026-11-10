
#include "crow.h"
#include "Database.h"
#include "Crypto.h"
#include "PasswordEntry.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <stdexcept>

#include <openssl/crypto.h>

using namespace std;

// Escape strings before placing them in JSON.
string jsonEscape(const string &value)
{
    string result;

    for (unsigned char c : value)
    {
        switch (c)
        {
        case '"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            if (c < 0x20)
            {
                result += ' ';
            }
            else
            {
                result += static_cast<char>(c);
            }
        }
    }

    return result;
}

// Convert the encrypted record back to PasswordEntry.
PasswordEntry deserializeEntry(
    const string &encryptedText)
{
    istringstream input(encryptedText);

    string service;
    string username;
    string password;
    string category;

    if (!(input >> quoted(service) >> quoted(username) >> quoted(password) >> quoted(category)))
    {
        throw runtime_error("Invalid encrypted record format.");
    }

    return PasswordEntry(
        service,
        username,
        password,
        category);
}

string readFile(const string &path)
{
    ifstream file(path, ios::binary);

    if (!file)
    {
        throw runtime_error("File not found: " + path);
    }

    stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}

int main()
{
    try
    {
        // IMPORTANT: Use the same database as your CLI.
        Database database("vaultx.db");

        string masterPassword;
        bool unlocked = false;

        crow::SimpleApp app;

        // ------------------------------------------
        // FRONTEND
        // ------------------------------------------

        CROW_ROUTE(app, "/")([]()
                             {
            try {
                crow::response response(
                    200,
                    readFile("frontend/index.html")
                );

                response.set_header(
                    "Content-Type",
                    "text/html"
                );

                return response;
            }
            catch (const exception& e) {
                return crow::response(500, e.what());
            } });

        CROW_ROUTE(app, "/css/<path>")(
            [](const string &path)
            {
                try
                {
                    crow::response response(
                        200,
                        readFile("frontend/css/" + path));

                    response.set_header(
                        "Content-Type",
                        "text/css");

                    return response;
                }
                catch (const exception &e)
                {
                    return crow::response(404, e.what());
                }
            });

        CROW_ROUTE(app, "/js/<path>")(
            [](const string &path)
            {
                try
                {
                    crow::response response(
                        200,
                        readFile("frontend/js/" + path));

                    response.set_header(
                        "Content-Type",
                        "application/javascript");

                    return response;
                }
                catch (const exception &e)
                {
                    return crow::response(404, e.what());
                }
            });

        // ------------------------------------------
        // HEALTH CHECK
        // ------------------------------------------

        CROW_ROUTE(app, "/api/health")([]()
                                       {
            crow::json::wvalue result;

            result["status"] = "success";
            result["message"] = "VaultX API is running";

            return result; });

        // ------------------------------------------
        // UNLOCK VAULT
        // ------------------------------------------

        CROW_ROUTE(app, "/api/unlock")
            .methods(crow::HTTPMethod::Post)([&](const crow::request &request)
                                             {
            try {
                auto body = crow::json::load(request.body);

                if (!body || !body.has("masterPassword")) {
                    return crow::response(
                        400,
                        "Master password is required."
                    );
                }

                string candidate =
                    body["masterPassword"].s();

                if (candidate.empty() || candidate.size() > 1024) {
                    return crow::response(
                        400,
                        "Invalid master password."
                    );
                }

                // Verify or initialize using the existing database.
                database.initializeOrVerifyMasterPassword(candidate);

                masterPassword = candidate;
                unlocked = true;

                crow::json::wvalue result;

                result["status"] = "success";
                result["message"] = "Vault unlocked";

                return crow::response(result);
            }
            catch (const exception& e) {
                cerr << "Unlock failed: " << e.what() << '\n';

                return crow::response(
                    401,
                    "Could not unlock vault. Check your master password."
                );
            } });

        // ------------------------------------------
        // LOCK VAULT
        // ------------------------------------------

        CROW_ROUTE(app, "/api/lock")
            .methods(crow::HTTPMethod::Post)([&](const crow::request &)
                                             {
            if (!masterPassword.empty()) {
                OPENSSL_cleanse(
                    masterPassword.data(),
                    masterPassword.size()
                );
            }

            masterPassword.clear();
            unlocked = false;

            crow::json::wvalue result;

            result["status"] = "success";
            result["message"] = "Vault locked";

            return crow::response(result); });

        // ------------------------------------------
        // GET SAVED DATABASE RECORDS
        // ------------------------------------------

        CROW_ROUTE(app, "/api/entries")
        ([&]()
         {
            try {
                if (!unlocked) {
                    return crow::response(
                        401,
                        "Vault is locked."
                    );
                }

                vector<StoredEntry> entries =
                    database.getAllEntries();

                string json = "[";

                bool first = true;

                for (const auto& stored : entries) {
                    string decrypted = Crypto::decrypt(
                        stored.encryptedData,
                        masterPassword
                    );

                    PasswordEntry entry =
                        deserializeEntry(decrypted);

                    if (!first) {
                        json += ",";
                    }

                    first = false;

                    json += "{";
                    json += "\"id\":" +
                        to_string(stored.id) + ",";

                    json += "\"service\":\"" +
                        jsonEscape(entry.getService()) + "\",";

                    json += "\"username\":\"" +
                        jsonEscape(entry.getUsername()) + "\",";

                    json += "\"password\":\"" +
                        jsonEscape(entry.getPassword()) + "\",";

                    json += "\"category\":\"" +
                        jsonEscape(entry.getCategory()) + "\"";

                    json += "}";
                }

                json += "]";

                crow::response response(200, json);

                response.set_header(
                    "Content-Type",
                    "application/json"
                );

                response.set_header(
                    "Cache-Control",
                    "no-store"
                );

                return response;
            }
            catch (const exception& e) {
                cerr << "Retrieval error: " << e.what() << '\n';

                return crow::response(
                    500,
                    "Could not retrieve vault records."
                );
            } });

        CROW_ROUTE(app, "/api/entries").methods(crow::HTTPMethod::POST)([&](const crow::request &req)
                                                                        {
    try {
        if (!unlocked) {
            crow::response res;
            res.code = 401;
            res.body = R"({"error":"Vault is locked"})";
            return res;
        }

        auto body = crow::json::load(req.body);

        if (!body) {
            crow::response res;
            res.code = 400;
            res.body = R"({"error":"Invalid JSON"})";
            return res;
        }

        auto getString = [&](const char* key) -> string {
            if (!body.has(key) ||
                body[key].t() != crow::json::type::String) {
                return "";
            }
            return body[key].s();
        };

        string title = getString("title");
        string username = getString("username");
        string password = getString("password");
        string category = getString("folder");

        if (title.empty() || username.empty() || password.empty()) {
            crow::response res;
            res.code = 400;
            res.body = R"({"error":"Title, username and password are required"})";
            return res;
        }

        if (password.length() < 6) {
            crow::response res;
            res.code = 400;
            res.body = R"({"error":"Password must contain at least 6 characters"})";
            return res;
        }

        if (category.empty()) {
            category = "Personal";
        }

        // Serialize the entry in the same format used by GET /api/entries.
        stringstream data;
        data << quoted(title) << " "
             << quoted(username) << " "
             << quoted(password) << " "
             << quoted(category);

        // Encrypt before storing in SQLite.
        EncryptedData encrypted =
            Crypto::encrypt(data.str(), masterPassword);

        database.insertEntry(encrypted);

        crow::response res;
        res.code = 201;
        res.body = R"({"success":true,"message":"Record saved successfully"})";
        res.set_header("Content-Type", "application/json");
        return res;

    } catch (const exception& e) {
        cerr << "Error saving record: " << e.what() << endl;

        crow::response res;
        res.code = 500;
        res.body = R"({"error":"Could not save record"})";
        return res;
    } });

        // ------------------------------------------
        // START SERVER
        // ------------------------------------------

        cout << "\n================================\n";
        cout << "       VAULTX BACKEND\n";
        cout << "================================\n";
        cout << "Database: vaultx.db\n";
        cout << "Website:  http://127.0.0.1:18080\n";
        cout << "API:      http://127.0.0.1:18080/api/health\n";
        cout << "Press CTRL+C to stop.\n\n";

        app.bindaddr("127.0.0.1")
            .port(18080)
            .multithreaded()
            .run();
    }
    catch (const exception &e)
    {
        cerr << "Fatal server error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
