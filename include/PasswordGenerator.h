
#ifndef PASSWORDGENERATOR_H
#define PASSWORDGENERATOR_H

#include <string>

using namespace std;

class PasswordGenerator {
public:
    static string generatePassword(
        int length,
        bool uppercase,
        bool lowercase,
        bool numbers,
        bool specialCharacters
    );
};

#endif
