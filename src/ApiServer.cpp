#include "ApiServer.h"

#include "Entry.h"
#include "PasswordAnalyzer.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <unordered_map>

using namespace std;
using namespace std::chrono;

namespace {

constexpr minutes IDLE_LIMIT{15};  // vault auto-locks after this much inactivity

// ---------------------------------------------------------------- JSON helpers
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

crow::json::rvalue parseBody(const crow::request& req) {
    auto body = crow::json::load(req.body);
    if (!body || body.t() != crow::json::type::Object)
        throw ApiError(400, "Invalid JSON body.");
    return body;
}

string bodyString(const crow::json::rvalue& body, const char* key) {
    if (!body.has(key) || body[key].t() != crow::json::type::String) return "";
    return string(body[key].s());
}

bool requireBool(const crow::json::rvalue& body, const char* key) {
    if (!body.has(key)) throw ApiError(400, string("Missing field: ") + key);

    auto t = body[key].t();
    if (t != crow::json::type::True && t != crow::json::type::False)
        throw ApiError(400, string("Field must be true or false: ") + key);

    return t == crow::json::type::True;
}

// Item list for the UI: no secrets or notes, but with a strength score and a
// "reused" flag computed here so passwords never have to leave the server.
// Works on Entry pointers: any type that exposes an auditPassword() is scored.
crow::json::wvalue listJson(const vector<unique_ptr<Entry>>& entries) {
    unordered_map<string, int> uses;
    for (const auto& e : entries)
        if (!e->deleted() && !e->auditPassword().empty()) uses[e->auditPassword()]++;

    crow::json::wvalue list = crow::json::wvalue::list();
    size_t i = 0;

    for (const auto& e : entries) {
        crow::json::wvalue w = e->toJson(false);
        string password = e->auditPassword();

        if (!password.empty()) {
            w["strength"] = PasswordAnalyzer::analyze(password).score;
            w["reused"] = !e->deleted() && uses[password] > 1;
        }

        list[i++] = std::move(w);
    }

    return list;
}

// ---------------------------------------------------------------- static files
bool safeFileName(const string& name) {
    if (name.empty() || name.size() > 64 || name.find("..") != string::npos) return false;

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

// ================================================================ middleware
void SecurityHeaders::after_handle(crow::request& req, crow::response& res, context&) {
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "no-referrer");
    res.set_header("Content-Security-Policy",
                   "default-src 'self'; img-src 'self' data:; "
                   "object-src 'none'; base-uri 'none'; frame-ancestors 'none'");

    if (req.url.rfind("/api/", 0) == 0) res.set_header("Cache-Control", "no-store");
}

// ================================================================ throttle
void LoginThrottle::check() const {
    auto now = steady_clock::now();

    if (now < lockedUntil_) {
        auto wait = duration_cast<seconds>(lockedUntil_ - now).count() + 1;
        throw ApiError(429, "Too many attempts. Try again in " + to_string(wait) + " seconds.");
    }
}

void LoginThrottle::recordFailure() {
    if (++failures_ >= 5) {
        int delay = 15 << min(failures_ - 5, 5);
        lockedUntil_ = steady_clock::now() + seconds(min(delay, 300));
    }
}

// ================================================================ ApiServer
ApiServer::ApiServer(PasswordVault& vault, int port) : vault_(vault), port_(port) {
    app_.loglevel(crow::LogLevel::Warning);

    registerStaticRoutes();
    registerAuthRoutes();
    registerEntryRoutes();
    startIdleWatcher();
}

// Blocks DNS-rebinding (Host) and cross-site requests (Origin).
bool ApiServer::hostAllowed(const crow::request& req) const {
    string host = req.get_header_value("Host");
    return host == "127.0.0.1:" + to_string(port_) || host == "localhost:" + to_string(port_);
}

bool ApiServer::originAllowed(const crow::request& req) const {
    string origin = req.get_header_value("Origin");
    return origin.empty() || origin == "http://127.0.0.1:" + to_string(port_) ||
           origin == "http://localhost:" + to_string(port_);
}

template <class Fn>
crow::response ApiServer::guarded(const crow::request& req, bool needsAuth, Fn&& fn) {
    lock_guard<mutex> lock(gate_);

    try {
        if (!hostAllowed(req)) throw ApiError(403, "Forbidden.");

        if (req.method != crow::HTTPMethod::Get && !originAllowed(req))
            throw ApiError(403, "Forbidden.");

        if (needsAuth) {
            if (!vault_.isUnlocked()) throw ApiError(401, "Vault is locked.");
            lastActive_ = Clock::now();
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

void ApiServer::registerStaticRoutes() {
    // Fixed locations only: no path traversal.
    CROW_ROUTE(app_, "/")([this](const crow::request& req) {
        if (!hostAllowed(req)) return fail(403, "Forbidden.");
        return serveFile("frontend/index.html", "text/html; charset=utf-8");
    });

    CROW_ROUTE(app_, "/css/<string>")([this](const crow::request& req, const string& name) {
        if (!hostAllowed(req) || !safeFileName(name)) return fail(404, "Not found.");
        return serveFile("frontend/css/" + name, "text/css; charset=utf-8");
    });

    CROW_ROUTE(app_, "/js/<string>")([this](const crow::request& req, const string& name) {
        if (!hostAllowed(req) || !safeFileName(name)) return fail(404, "Not found.");
        return serveFile("frontend/js/" + name, "application/javascript; charset=utf-8");
    });
}

void ApiServer::registerAuthRoutes() {
    CROW_ROUTE(app_, "/api/health")([this](const crow::request& req) {
        return guarded(req, false, [&] {
            return reply(200, R"({"status":"success","message":"VaultX API is running"})");
        });
    });

    CROW_ROUTE(app_, "/api/status")([this](const crow::request& req) {
        return guarded(req, false, [&] {
            crow::json::wvalue w;
            w["initialized"] = vault_.isInitialized();
            w["unlocked"] = vault_.isUnlocked();
            return reply(200, w.dump());
        });
    });

    CROW_ROUTE(app_, "/api/unlock").methods(crow::HTTPMethod::Post)(
        [this](const crow::request& req) {
            return guarded(req, false, [&] {
                throttle_.check();

                auto body = parseBody(req);
                if (!body.has("masterPassword") ||
                    body["masterPassword"].t() != crow::json::type::String)
                    throw ApiError(400, "Master password is required.");

                try {
                    vault_.unlock(string(body["masterPassword"].s()));
                }
                catch (const ApiError& e) {
                    if (e.code() == 401) throttle_.recordFailure();
                    throw;
                }

                throttle_.reset();
                lastActive_ = Clock::now();
                return reply(200, R"({"status":"success","message":"Vault unlocked"})");
            });
        });

    CROW_ROUTE(app_, "/api/lock").methods(crow::HTTPMethod::Post)(
        [this](const crow::request& req) {
            return guarded(req, false, [&] {
                vault_.lock();
                return reply(200, R"({"status":"success","message":"Vault locked"})");
            });
        });

    CROW_ROUTE(app_, "/api/change-password").methods(crow::HTTPMethod::Post)(
        [this](const crow::request& req) {
            return guarded(req, true, [&] {
                throttle_.check();

                auto body = parseBody(req);

                try {
                    vault_.changePassword(bodyString(body, "current"), bodyString(body, "next"));
                }
                catch (const ApiError& e) {
                    if (e.code() == 403) throttle_.recordFailure();
                    throw;
                }

                throttle_.reset();
                return reply(200, R"({"success":true,"message":"Master password changed"})");
            });
        });
}

void ApiServer::registerEntryRoutes() {
    CROW_ROUTE(app_, "/api/entries")
        .methods(crow::HTTPMethod::Get, crow::HTTPMethod::Post)([this](const crow::request& req) {
            return guarded(req, true, [&] {
                if (req.method == crow::HTTPMethod::Post) {
                    const Entry& saved = vault_.add(Entry::fromRequest(parseBody(req)));
                    return reply(201, saved.toJson(false).dump());
                }

                crow::response res = reply(200, listJson(vault_.list()).dump());

                if (vault_.skippedCount() > 0)
                    res.set_header("X-Vault-Skipped", to_string(vault_.skippedCount()));

                return res;
            });
        });

    CROW_ROUTE(app_, "/api/entries/<int>")
        .methods(crow::HTTPMethod::Get, crow::HTTPMethod::Put, crow::HTTPMethod::Delete)(
            [this](const crow::request& req, int id) {
                return guarded(req, true, [&] {
                    if (req.method == crow::HTTPMethod::Put) {
                        const Entry& saved = vault_.update(id, Entry::fromRequest(parseBody(req)));
                        return reply(200, saved.toJson(false).dump());
                    }

                    if (req.method == crow::HTTPMethod::Delete) {
                        vault_.remove(id);
                        return reply(200, R"({"success":true})");
                    }

                    return reply(200, vault_.get(id).toJson(true).dump());  // full record
                });
            });

    CROW_ROUTE(app_, "/api/entries/<int>/favorite").methods(crow::HTTPMethod::Patch)(
        [this](const crow::request& req, int id) {
            return guarded(req, true, [&] {
                vault_.setFavorite(id, requireBool(parseBody(req), "favorite"));
                return reply(200, R"({"success":true})");
            });
        });

    CROW_ROUTE(app_, "/api/entries/<int>/trash").methods(crow::HTTPMethod::Patch)(
        [this](const crow::request& req, int id) {
            return guarded(req, true, [&] {
                vault_.setDeleted(id, requireBool(parseBody(req), "deleted"));
                return reply(200, R"({"success":true})");
            });
        });
}

void ApiServer::startIdleWatcher() {
    thread([this] {
        while (true) {
            this_thread::sleep_for(seconds(15));

            lock_guard<mutex> lock(gate_);
            if (vault_.isUnlocked() && Clock::now() - lastActive_ > IDLE_LIMIT) vault_.lock();
        }
    }).detach();
}

void ApiServer::run() {
    if (!ifstream("frontend/index.html"))
        cerr << "Warning: frontend/ not found. Run VaultX from the project folder.\n";

    cout << "\n================================\n"
         << "       VAULTX BACKEND\n"
         << "================================\n"
         << "Website: http://127.0.0.1:" << port_ << "\n"
         << "Press CTRL+C to stop.\n\n";

    app_.bindaddr("127.0.0.1").port(port_).multithreaded().run();
}
