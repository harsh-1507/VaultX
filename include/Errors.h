#ifndef ERRORS_H
#define ERRORS_H

#include <stdexcept>
#include <string>

using namespace std;

// An error that maps directly to an HTTP status code.
class ApiError : public std::runtime_error {
    int statusCode;

public:
    ApiError(int code, const std::string& message)
        : std::runtime_error(message), statusCode(code) {}

    int code() const { return statusCode; }
};

#endif
