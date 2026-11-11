#include "crow.h"

#include "Database.h"
#include "Entry.h"
#include "EntryStore.h"
#include "Errors.h"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

using namespace std;
using namespace std::chrono;

namespace {

constexpr int PORT = 18080;
constexpr minutes IDLE_LIMIT{15};  // vault auto-locks after this much inactivity

// ---------------------------------------------------------------- headers
struct SecurityHeaders {
    struct context {};

    void before_handle(crow::request&, crow::response&, context&) {}

    void after_handle(crow::request& req, crow::response& res, context&) {
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("X-Frame-Options", "DENY");
        res.set_header("Referrer-Policy", "no-referrer");
        res.set_header("Content-Security-Policy",
                       "default-src 'self'; img-src 'self' data:; "
                       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'");

        if (req.url.rfind("/api/", 0) == 0)
            res.set_header("Cache-Control", "no-store");
    }
};

// ---------------------------------------------------------------- state
struct State {
    Database& db;
    EntryStore store;
    mutex gate;  // Crow is multithreaded; everything below is guarded by this
    int failedUnlocks = 0;
    steady_clock::time_point lockedUntil{};
    steady_clock::time_point lastActive = steady_clock::now();

    explicit State(Database& database) : db(database), store(database) {}
};

// ---------------------------------------------------------------- helpers
crow::response reply(int code, const string& json) {
    crow::response res(code, json);
    res.set_header("Content-Type", "application/json");
    return res;
}

crow::response fail(int code, const string& message) {
    crow::json::wvalue w;
    w["error"] = message;
    return reply(code, w.dump());
}

string hostPart(const string& prefix) {
    return prefix + "127.0.0.1:" + to_string(PORT);
}

// Blocks DNS-rebinding (Host) and cross-site requests (Origin).
bool hostAllowed(const crow::request& req) {
    string host = req.get_header_value("Host");
    return host == "127.0.0.1:" + to_string(PORT) ||
           host == "localhost:" + to_string(PORT);
}

bool originAllowed(const crow::request& req) {
    string origin = req.get_header_value("Origin");
    return origin.empty() ||
           origin == "http://127.0.0.1:" + to_string(PORT) ||
           origin == "http://localhost:" + to_string(PORT);
}

crow::json::rvalue parseBody(const crow::request& req) {
    auto body = crow::json::load(req.body);
    if (!body || body.t() != crow::json::type::Object)
        throw ApiError(400, "Invalid JSON body.");
    return body;
}

bool requireBool(const crow::json::rvalue& body, const char* key) {
    if (!body.has(key)) throw ApiError(400, string("Missing field: ") + key);

    auto t = body[key].t();
    if (t != crow::json::type::True && t != crow::json::type::False)
        throw ApiError(400, string("Field must be true or false: ") + key);

    return t == crow::json::type::True;
}

// Runs a handler with locking, host/origin checks, auth and uniform errors.
template <class Fn>
crow::response guarded(State& s, const crow::request& req, bool needsAuth, Fn&& fn) {
    lock_guard<mutex> lock(s.gate);

    try {
        if (!hostAllowed(req)) throw ApiError(403, "Forbidden.");

        if (req.method != crow::HTTPMethod::Get && !originAllowed(req))
            throw ApiError(403, "Forbidden.");

        if (needsAuth) {
            if (!s.store.isUnlocked()) throw ApiError(401, "Vault is locked.");
            s.lastActive = steady_clock::now();
        }

        return fn();
    }
    catch (const ApiError& e) {
        return fail(e.code(), e.what());
    }
    catch (const exception& e) {
        cerr << "Server error: " << e.what() << '\n';
        return fail(500, "Internal server error.");
    }
}

// ---------------------------------------------------------------- static files
bool safeFileName(const string& name) {
    if (name.empty() || name.size() > 64 || name.find("..") != string::npos)
        return false;

    for (unsigned char c : name)
        if (!isalnum(c) && c != '.' && c != '-' && c != '_') return false;

    return true;
}

crow::response serveFile(const string& path, const string& mime) {
    ifstream file(path, ios::binary);
    if (!file) return fail(404, "Not found.");

    stringstream buffer;
    buffer << file.rdbuf();

    crow::response res(200, buffer.str());
    res.set_header("Content-Type", mime);
    res.set_header("Cache-Control", "no-cache");
    return res;
}

}  // namespace

int main() {
    try {
        const char* dbPath = getenv("VAULTX_DB");
        Database database(dbPath ? dbPath : "vaultx.db");
        database.createTables();  // fresh installs have no tables yet

        State state(database);
        crow::App<SecurityHeaders> app;
        app.loglevel(crow::LogLevel::Warning);

        // ----- frontend (fixed locations only, no path traversal) -----
        CROW_ROUTE(app, "/")([&](const crow::request& req) {
            if (!hostAllowed(req)) return fail(403, "Forbidden.");
            return serveFile("frontend/index.html", "text/html; charset=utf-8");
        });

        CROW_ROUTE(app, "/css/<string>")([&](const crow::request& req, const string& name) {
            if (!hostAllowed(req) || !safeFileName(name)) return fail(404, "Not found.");
            return serveFile("frontend/css/" + name, "text/css; charset=utf-8");
        });

        CROW_ROUTE(app, "/js/<string>")([&](const crow::request& req, const string& name) {
            if (!hostAllowed(req) || !safeFileName(name)) return fail(404, "Not found.");
            return serveFile("frontend/js/" + name, "application/javascript; charset=utf-8");
        });

        // ----- health -----
        CROW_ROUTE(app, "/api/health")([&](const crow::request& req) {
            return guarded(state, req, false, [&] {
                return reply(200, R"({"status":"success","message":"VaultX API is running"})");
            });
        });

        CROW_ROUTE(app, "/api/status")([&](const crow::request& req) {
            return guarded(state, req, false, [&] {
                crow::json::wvalue w;
                w["initialized"] = state.db.hasMasterPassword();
                w["unlocked"] = state.store.isUnlocked();
                return reply(200, w.dump());
            });
        });

        // ----- unlock / lock -----
        CROW_ROUTE(app, "/api/unlock").methods(crow::HTTPMethod::Post)(
            [&](const crow::request& req) {
                return guarded(state, req, false, [&] {
                    auto now = steady_clock::now();

                    if (now < state.lockedUntil) {
                        auto wait = duration_cast<seconds>(state.lockedUntil - now).count() + 1;
                        throw ApiError(429, "Too many attempts. Try again in " +
                                                to_string(wait) + " seconds.");
                    }

                    auto body = parseBody(req);
                    if (!body.has("masterPassword") ||
                        body["masterPassword"].t() != crow::json::type::String)
                        throw ApiError(400, "Master password is required.");

                    try {
                        state.store.unlock(string(body["masterPassword"].s()));
                    }
                    catch (const ApiError& e) {
                        if (e.code() == 401 && ++state.failedUnlocks >= 5) {
                            int delay = 15 << min(state.failedUnlocks - 5, 5);
                            state.lockedUntil = now + seconds(min(delay, 300));
                        }
                        throw;
                    }

                    state.failedUnlocks = 0;
                    state.lastActive = now;
                    return reply(200, R"({"status":"success","message":"Vault unlocked"})");
                });
            });

        CROW_ROUTE(app, "/api/lock").methods(crow::HTTPMethod::Post)(
            [&](const crow::request& req) {
                return guarded(state, req, false, [&] {
                    state.store.lock();
                    return reply(200, R"({"status":"success","message":"Vault locked"})");
                });
            });

        // ----- collection -----
        CROW_ROUTE(app, "/api/entries")
            .methods(crow::HTTPMethod::Get, crow::HTTPMethod::Post)(
                [&](const crow::request& req) {
                    return guarded(state, req, true, [&] {
                        if (req.method == crow::HTTPMethod::Post) {
                            Entry saved = state.store.add(Entry::fromRequest(parseBody(req)));
                            return reply(201, saved.toJson().dump());
                        }

                        crow::json::wvalue list = crow::json::wvalue::list();
                        size_t i = 0;
                        for (const Entry& e : state.store.list()) list[i++] = e.toJson();

                        crow::response res = reply(200, list.dump());
                        if (state.store.skippedCount() > 0)
                            res.set_header("X-Vault-Skipped",
                                           to_string(state.store.skippedCount()));
                        return res;
                    });
                });

        // ----- single item -----
        CROW_ROUTE(app, "/api/entries/<int>")
            .methods(crow::HTTPMethod::Get, crow::HTTPMethod::Put,
                     crow::HTTPMethod::Delete)(
                [&](const crow::request& req, int id) {
                    return guarded(state, req, true, [&] {
                        if (req.method == crow::HTTPMethod::Put) {
                            Entry saved = state.store.update(id, Entry::fromRequest(parseBody(req)));
                            return reply(200, saved.toJson().dump());
                        }

                        if (req.method == crow::HTTPMethod::Delete) {
                            state.store.remove(id);
                            return reply(200, R"({"success":true})");
                        }

                        for (const Entry& e : state.store.list())
                            if (e.id == id) return reply(200, e.toJson().dump());

                        throw ApiError(404, "Item not found.");
                    });
                });

        CROW_ROUTE(app, "/api/entries/<int>/favorite").methods(crow::HTTPMethod::Patch)(
            [&](const crow::request& req, int id) {
                return guarded(state, req, true, [&] {
                    state.store.setFavorite(id, requireBool(parseBody(req), "favorite"));
                    return reply(200, R"({"success":true})");
                });
            });

        CROW_ROUTE(app, "/api/entries/<int>/trash").methods(crow::HTTPMethod::Patch)(
            [&](const crow::request& req, int id) {
                return guarded(state, req, true, [&] {
                    state.store.setDeleted(id, requireBool(parseBody(req), "deleted"));
                    return reply(200, R"({"success":true})");
                });
            });

        // ----- auto-lock when idle -----
        thread([&] {
            while (true) {
                this_thread::sleep_for(seconds(15));
                lock_guard<mutex> lock(state.gate);
                if (state.store.isUnlocked() &&
                    steady_clock::now() - state.lastActive > IDLE_LIMIT)
                    state.store.lock();
            }
        }).detach();

        if (!ifstream("frontend/index.html"))
            cerr << "Warning: frontend/ not found. Run VaultX from the project folder.\n";

        cout << "\n================================\n"
             << "       VAULTX BACKEND\n"
             << "================================\n"
             << "Website: http://127.0.0.1:" << PORT << "\n"
             << "Press CTRL+C to stop.\n\n";

        app.bindaddr("127.0.0.1").port(PORT).multithreaded().run();
    }
    catch (const exception& e) {
        cerr << "Fatal server error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
