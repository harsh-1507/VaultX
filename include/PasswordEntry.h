
#ifndef PASSWORDENTRY_H
#define PASSWORDENTRY_H

#include <string>

using namespace std;

class PasswordEntry {
private:
    string service;
    string username;
    string password;
    string category;

public:
    PasswordEntry(string service,
                  string username,
                  string password,
                  string category);

    string getService() const;
    string getUsername() const;
    string getPassword() const;
    string getCategory() const;

    void setUsername(string newUsername);
    void setPassword(string newPassword);
    void setCategory(string newCategory);
};

#endif
