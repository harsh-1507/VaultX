#ifndef LOGINTHROTTLE_H
#define LOGINTHROTTLE_H

#include <chrono>

using namespace std;

// Slows down master-password guessing.
//
// Behaviour:
//  * Wrong passwords are answered at once until `freeAttempts` failures in a
//    row (default 5) have happened.
//  * From then on every failure locks attempts out for baseDelay, then doubles
//    the wait each time (15 s, 30 s, 60 s ...), never more than maxDelay (5 min).
//    The lockout is therefore always temporary: there is no permanent lockout.
//  * A correct password clears the counter.
//  * If no failure has happened for `forgetAfter` (default 10 min), the old
//    failures are forgotten, so a typo made yesterday does not count today.
//  * State lives in memory only. Restarting the program resets it. That is a
//    deliberate trade-off for a local single-user app: persisting it would let
//    a crash or a stray file lock the owner out, and anyone who can restart the
//    process or read the database file can attack it offline anyway (the
//    600,000-round PBKDF2 is what protects against that).
//
// Not thread-safe by itself; ApiServer calls it while holding its gate mutex.
class LoginThrottle {
public:
    using Clock = chrono::steady_clock;

private:
    int freeAttempts_;
    chrono::seconds baseDelay_;
    chrono::seconds maxDelay_;
    chrono::seconds forgetAfter_;

    int failures_ = 0;
    Clock::time_point lockedUntil_{};
    Clock::time_point lastFailure_{};

public:
    explicit LoginThrottle(int freeAttempts = 5, chrono::seconds baseDelay = chrono::seconds(15),
                           chrono::seconds maxDelay = chrono::seconds(300),
                           chrono::seconds forgetAfter = chrono::seconds(600))
        : freeAttempts_(freeAttempts), baseDelay_(baseDelay), maxDelay_(maxDelay),
          forgetAfter_(forgetAfter) {}

    // Throws ApiError(429) while locked out.
    void check(Clock::time_point now = Clock::now()) const;

    void recordFailure(Clock::time_point now = Clock::now());
    void reset() { failures_ = 0; lockedUntil_ = Clock::time_point{}; }

    int failures() const { return failures_; }

    // Whole seconds (rounded up) until attempts are allowed again, 0 if allowed.
    long long secondsRemaining(Clock::time_point now = Clock::now()) const;
};

#endif
