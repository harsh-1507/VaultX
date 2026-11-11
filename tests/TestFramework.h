#ifndef TESTFRAMEWORK_H
#define TESTFRAMEWORK_H

// A deliberately tiny, dependency-free test harness (no network access or
// package manager needed, works unchanged on MSYS2 UCRT64).
//
//   TEST_CASE(name_of_test) { CHECK(1 + 1 == 2); }
//
// A failed CHECK stops that test case and reports file, line and expression.
// Test executables return 0 only if every test case passed, so CTest works.

#include <chrono>
#include <filesystem>
#include <functional>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

struct TestFailure : runtime_error {
    using runtime_error::runtime_error;
};

struct TestCase {
    string name;
    function<void()> run;
};

inline vector<TestCase>& testRegistry() {
    static vector<TestCase> registry;
    return registry;
}

struct TestRegistrar {
    TestRegistrar(const string& name, function<void()> run) {
        testRegistry().push_back({name, std::move(run)});
    }
};

#define TEST_CASE(name)                                       \
    static void name();                                       \
    static TestRegistrar registrar_##name(#name, name);       \
    static void name()

#define TEST_FAIL_(message) \
    throw TestFailure(string(__FILE__) + ":" + to_string(__LINE__) + ": " + (message))

#define CHECK(condition) \
    do { if (!(condition)) TEST_FAIL_(string("CHECK failed: ") + #condition); } while (0)

#define CHECK_EQ(actual, expected)                                                      \
    do {                                                                                \
        auto a_ = (actual);                                                             \
        auto e_ = (expected);                                                           \
        if (!(a_ == e_)) {                                                              \
            ostringstream o_;                                                           \
            o_ << "CHECK_EQ failed: " #actual " == " #expected "  (got " << a_          \
               << ", expected " << e_ << ")";                                           \
            TEST_FAIL_(o_.str());                                                       \
        }                                                                               \
    } while (0)

// Passes only if `expression` throws something of type ExceptionType.
#define CHECK_THROWS_AS(expression, ExceptionType)                                      \
    do {                                                                                \
        bool threw_ = false;                                                            \
        try { (void)(expression); }                                                     \
        catch (const ExceptionType&) { threw_ = true; }                                 \
        catch (...) { TEST_FAIL_("wrong exception type from: " #expression); }          \
        if (!threw_) TEST_FAIL_("expected " #ExceptionType " from: " #expression);      \
    } while (0)

#define CHECK_THROWS(expression)                                                        \
    do {                                                                                \
        bool threw_ = false;                                                            \
        try { (void)(expression); } catch (...) { threw_ = true; }                      \
        if (!threw_) TEST_FAIL_("expected an exception from: " #expression);            \
    } while (0)

// A private directory for one test; deleted afterwards. Tests never touch the
// real vaultx.db: every database lives inside one of these.
class TempDir {
    filesystem::path path_;

public:
    TempDir() {
        random_device rd;
        path_ = filesystem::temp_directory_path() /
                ("vaultx_test_" + to_string(rd()) + "_" + to_string(rd()));
        filesystem::create_directories(path_);
    }

    ~TempDir() {
        error_code ignored;
        filesystem::remove_all(path_, ignored);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    string file(const string& name) const { return (path_ / name).string(); }
    const filesystem::path& path() const { return path_; }
};

#endif
