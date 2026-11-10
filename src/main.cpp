#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <iostream>
#include <string>
#include <limits>
#include <stdexcept>

#include "Database.h"
#include "PasswordVault.h"
#include "PasswordEntry.h"
#include "PasswordGenerator.h"
#include "PasswordAnalyzer.h"

using namespace std;

// Handles restoration of terminal password visibility.
class ConsoleEchoGuard {
private:
    HANDLE inputHandle;
    DWORD originalMode;
    bool active;

public:
    ConsoleEchoGuard()
        : inputHandle(GetStdHandle(STD_INPUT_HANDLE)),
          originalMode(0),
          active(false) {

        if (inputHandle == INVALID_HANDLE_VALUE ||
            !GetConsoleMode(inputHandle, &originalMode)) {
            throw runtime_error("Could not access Windows console.");
        }

        DWORD newMode = originalMode & ~ENABLE_ECHO_INPUT;

        if (!SetConsoleMode(inputHandle, newMode)) {
            throw runtime_error("Could not hide password input.");
        }

        active = true;
    }

    void restore() {
        if (active) {
            if (!SetConsoleMode(inputHandle, originalMode)) {
                throw runtime_error("Could not restore console settings.");
            }

            active = false;
        }
    }

    ~ConsoleEchoGuard() {
        if (active) {
            SetConsoleMode(inputHandle, originalMode);
        }
    }

    ConsoleEchoGuard(const ConsoleEchoGuard&) = delete;
    ConsoleEchoGuard& operator=(const ConsoleEchoGuard&) = delete;
};

class InputClosed : public runtime_error {
public:
    InputClosed() : runtime_error("Input stream closed.") {}
};

// Hidden password input.
string readPassword(const string& prompt) {
    cout << prompt << flush;

    ConsoleEchoGuard guard;

    string password;

    if (!getline(cin, password)) {
        throw InputClosed();
    }

    guard.restore();
    cout << '\n';

    return password;
}

// Read non-empty input.
string readNonEmpty(const string& prompt) {
    string value;

    cout << prompt;

    if (!getline(cin, value)) {
        throw InputClosed();
    }

    if (value.empty()) {
        throw invalid_argument("Input cannot be empty.");
    }

    return value;
}

// Read integer input.
int readChoice() {
    int choice;

    if (!(cin >> choice)) {
        if (cin.eof()) {
            throw InputClosed();
        }

        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        throw invalid_argument("Please enter a valid number.");
    }

    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    return choice;
}

// Read yes/no input.
bool readYesNo(const string& prompt) {
    while (true) {
        string answer = readNonEmpty(prompt);

        if (answer == "y" || answer == "Y") {
            return true;
        }

        if (answer == "n" || answer == "N") {
            return false;
        }

        cout << "Please enter y or n.\n";
    }
}

// Read account ID.
int readEntryId() {
    cout << "Enter account ID: ";

    int id = readChoice();

    if (id <= 0) {
        throw invalid_argument("ID must be positive.");
    }

    return id;
}

// Display menu.
void displayMenu() {
    cout << "\n========== VAULTX ==========\n";
    cout << "1. Add Account\n";
    cout << "2. View All Accounts\n";
    cout << "3. Search Account\n";
    cout << "4. Edit Account\n";
    cout << "5. Delete Account\n";
    cout << "6. Generate Password\n";
    cout << "7. Analyze Password\n";
    cout << "8. Exit\n";
    cout << "============================\n";
    cout << "Enter your choice: ";
}

// Add account.
void addAccount(PasswordVault& vault) {
    string service = readNonEmpty("Enter service name: ");
    string username = readNonEmpty("Enter username/email: ");
    string password = readPassword("Enter account password (hidden): ");
    string category = readNonEmpty("Enter category: ");

    PasswordEntry entry(service, username, password, category);

    if (vault.addEntry(entry)) {
        cout << "\nAccount added successfully!\n";
    }
}

// Search account.
void searchAccount(PasswordVault& vault) {
    string service = readNonEmpty("Enter service name to search: ");

    vault.searchByService(service);
}

// Edit account.
void editAccount(PasswordVault& vault) {
    int id = readEntryId();

    string username = readNonEmpty("Enter new username: ");
    string password = readPassword("Enter new password (hidden): ");
    string category = readNonEmpty("Enter new category: ");

    if (vault.editEntry(id, username, password, category)) {
        cout << "\nAccount updated successfully!\n";
    }
}

// Delete account.
void deleteAccount(PasswordVault& vault) {
    int id = readEntryId();

    bool confirm = readYesNo(
        "Are you sure you want to delete this account? (y/n): "
    );

    if (confirm) {
        if (vault.deleteEntry(id)) {
            cout << "\nAccount deleted successfully!\n";
        }
    } else {
        cout << "\nDeletion cancelled.\n";
    }
}

// Password generator.
void generatePassword() {
    cout << "\n====== PASSWORD GENERATOR ======\n";

    cout << "Enter password length (8-128): ";

    int length = readChoice();

    if (length < 8 || length > 128) {
        throw invalid_argument(
            "Password length must be between 8 and 128."
        );
    }

    bool uppercase = readYesNo("Include uppercase letters? (y/n): ");
    bool lowercase = readYesNo("Include lowercase letters? (y/n): ");
    bool numbers = readYesNo("Include numbers? (y/n): ");
    bool special = readYesNo("Include special characters? (y/n): ");

    if (!uppercase && !lowercase && !numbers && !special) {
        throw invalid_argument(
            "Select at least one character category."
        );
    }

    string password = PasswordGenerator::generatePassword(
        length,
        uppercase,
        lowercase,
        numbers,
        special
    );

    cout << "\nGenerated password:\n";
    cout << password << '\n';

    cout << "\nKeep this password somewhere secure.\n";
}

// Password analyzer.
void analyzePassword() {
    cout << "\n====== PASSWORD ANALYZER ======\n";

    string password = readPassword(
        "Enter password to analyze (hidden): "
    );

    PasswordAnalysis analysis =
        PasswordAnalyzer::analyze(password);

    cout << "\nPassword score: "
         << analysis.score << "/100\n";

    cout << "Password strength: "
         << analysis.strength << '\n';

    cout << "\nSuggestions:\n";

    if (analysis.suggestions.empty()) {
        cout << "Your password passed all implemented checks!\n";
    } else {
        for (const string& suggestion : analysis.suggestions) {
            cout << "- " << suggestion << '\n';
        }
    }
}

// Main application.
int main() {
    try {
        cout << "\n";
        cout << "============================\n";
        cout << "       WELCOME TO VAULTX    \n";
        cout << "============================\n";

        Database database("vaultx.db");

        database.createTables();

        string masterPassword = readPassword(
            "Enter master password (hidden): "
        );

        database.initializeOrVerifyMasterPassword(masterPassword);

        cout << "\nMaster password verified successfully!\n";

        PasswordVault vault(database, masterPassword);

        bool running = true;

        while (running) {
            try {
                displayMenu();

                int choice = readChoice();

                switch (choice) {
                    case 1:
                        addAccount(vault);
                        break;

                    case 2:
                        vault.displayAll();
                        break;

                    case 3:
                        searchAccount(vault);
                        break;

                    case 4:
                        editAccount(vault);
                        break;

                    case 5:
                        deleteAccount(vault);
                        break;

                    case 6:
                        generatePassword();
                        break;

                    case 7:
                        analyzePassword();
                        break;

                    case 8:
                        running = false;
                        cout << "\nVaultX closed successfully!\n";
                        break;

                    default:
                        cout << "\nInvalid choice. Select 1-8.\n";
                }
            }
            catch (const InputClosed&) {
                cout << "\nInput closed. Exiting VaultX.\n";
                running = false;
            }
            catch (const invalid_argument& e) {
                cout << "\nInvalid input: " << e.what() << '\n';
            }
            catch (const exception& e) {
                cout << "\nOperation failed: " << e.what() << '\n';
            }
        }

        return 0;
    }
    catch (const exception& e) {
        cerr << "\nVaultX error: " << e.what() << '\n';
        return 1;
    }
    catch (...) {
        cerr << "\nUnknown critical error occurred.\n";
        return 1;
    }
}
