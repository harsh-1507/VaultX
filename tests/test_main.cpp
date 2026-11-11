// Shared main() for every test executable. Usage: test_xxx [name-substring]
#include "TestFramework.h"

using namespace std;

int main(int argc, char** argv) {
    string filter = argc > 1 ? argv[1] : "";
    int passed = 0, failed = 0;

    for (const TestCase& test : testRegistry()) {
        if (!filter.empty() && test.name.find(filter) == string::npos) continue;

        auto start = chrono::steady_clock::now();
        try {
            test.run();
            passed++;
            auto ms = chrono::duration_cast<chrono::milliseconds>(
                          chrono::steady_clock::now() - start).count();
            cout << "[ PASS ] " << test.name << " (" << ms << " ms)\n";
        } catch (const exception& e) {
            failed++;
            cout << "[ FAIL ] " << test.name << "\n         " << e.what() << "\n";
        } catch (...) {
            failed++;
            cout << "[ FAIL ] " << test.name << "\n         unknown exception\n";
        }
    }

    cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
