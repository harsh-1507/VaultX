#ifndef APISERVER_H
#define APISERVER_H

#include "crow.h"

#include <chrono>
#include <mutex>
#include <string>

#include "Errors.h"
#include "PasswordVault.h"

using namespace std;

// Crow middleware: adds security headers to every response.
struct SecurityHeaders {
    struct context {};

    void before_handle(crow::request&, crow::response&, context&) {}
    void after_handle(crow::request& req, crow::response& res, context&);
};

// Slows down password guessing: 5 failures, then growing lockouts (max 5 min).
class LoginThrottle {
    int failures_ = 0;
    std::chrono::steady_clock::time_point lockedUntil_{};

public:
    void check() const;  // throws ApiError(429) while locked out
    void recordFailure();
    void reset() { failures_ = 0; }
};

// The HTTP layer: routes, request checks and JSON. Business logic stays in
// PasswordVault; this class only translates between HTTP and the vault.
class ApiServer {
    using Clock = std::chrono::steady_clock;

    PasswordVault& vault_;
    int port_;

    std::mutex gate_;  // Crow is multithreaded; the vault is not
    LoginThrottle throttle_;
    Clock::time_point lastActive_ = Clock::now();
    crow::App<SecurityHeaders> app_;

    void registerStaticRoutes();
    void registerAuthRoutes();
    void registerEntryRoutes();
    void startIdleWatcher();

    bool hostAllowed(const crow::request& req) const;
    bool originAllowed(const crow::request& req) const;

    // Runs a handler with locking, host/origin checks, auth and uniform errors.
    template <class Fn>
    crow::response guarded(const crow::request& req, bool needsAuth, Fn&& fn);

public:
    explicit ApiServer(PasswordVault& vault, int port = 18080);

    void run();  // blocks
};

#endif
