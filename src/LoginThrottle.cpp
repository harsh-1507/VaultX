#include "LoginThrottle.h"

#include <algorithm>
#include <string>

#include "Errors.h"

using namespace std;

long long LoginThrottle::secondsRemaining(Clock::time_point now) const {
    if (now >= lockedUntil_) return 0;

    auto left = chrono::duration_cast<chrono::milliseconds>(lockedUntil_ - now).count();
    return (left + 999) / 1000;  // round up so the client never retries too early
}

void LoginThrottle::check(Clock::time_point now) const {
    long long wait = secondsRemaining(now);

    if (wait > 0)
        throw ApiError(429, "Too many attempts. Try again in " + to_string(wait) + " seconds.");
}

void LoginThrottle::recordFailure(Clock::time_point now) {
    // Forget old failures after a quiet period.
    if (failures_ > 0 && now - lastFailure_ >= forgetAfter_) failures_ = 0;

    lastFailure_ = now;
    if (failures_ < 1000) failures_++;  // plenty; avoids any overflow

    if (failures_ < freeAttempts_) return;  // the Nth failure starts the first lockout

    int doublings = min(failures_ - freeAttempts_, 20);  // 2^20 * base fits easily
    chrono::seconds delay = baseDelay_ * (1LL << doublings);
    lockedUntil_ = now + min(delay, maxDelay_);
}
