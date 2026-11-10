
#include <iostream>
#include <string>
#include <limits>
#include <stdexcept>
#include "PasswordAnalyzer.h"
#include "PasswordEntry.h"
#include "PasswordVault.h"
#include "PasswordGenerator.h"

using namespace std;

void clearScreen()
{
    cout << "\033[2J\033[H" << flush;
}

void pauseScreen()
{
    cout << "\nPress Enter to continue...";
    cin.get();
}

bool getYesNo(const string &question)
{

    string answer;

    while (true)
    {

        cout << question << " (y/n): ";
        getline(cin, answer);

        if (answer == "y" || answer == "Y")
        {
            return true;
        }

        if (answer == "n" || answer == "N")
        {
            return false;
        }

        cout << "Invalid input! Enter y or n.\n";
    }
}

void displayMenu() {

    cout << "\n================================\n";
    cout << "             VAULTX\n";
    cout << "       PASSWORD MANAGER\n";
    cout << "================================\n";

    cout << "1. Add Account\n";
    cout << "2. View All Accounts\n";
    cout << "3. Search Account\n";
    cout << "4. Delete Account\n";
    cout << "5. Edit Account\n";
    cout << "6. Generate Password\n";
    cout << "7. Analyze Password Strength\n";
    cout << "8. Exit\n";

    cout << "================================\n";
    cout << "Enter your choice: ";
}

int main()
{

    PasswordVault vault;
    int choice;

    while (true)
    {

        displayMenu();

        if (!(cin >> choice))
        {

            cout << "\n[ERROR] Enter a valid number!\n";

            cin.clear();
            cin.ignore(
                numeric_limits<streamsize>::max(), '\n');

            continue;
        }

        cin.ignore(
            numeric_limits<streamsize>::max(), '\n');

        switch (choice)
        {

        case 1:
        {

            string service, username, password, category;

            cout << "\n===== ADD ACCOUNT =====\n";

            cout << "Service: ";
            getline(cin, service);

            cout << "Username: ";
            getline(cin, username);

            cout << "Password: ";
            getline(cin, password);

            cout << "Category: ";
            getline(cin, category);

            try
            {

                PasswordEntry entry(
                    service, username, password, category);

                vault.addEntry(entry);
            }
            catch (const invalid_argument &e)
            {
                cout << "\n[VALIDATION ERROR] "
                     << e.what() << endl;
            }
            catch (const exception &e)
            {
                cout << "\n[ERROR] " << e.what() << endl;
            }

            pauseScreen();
            break;
        }

        case 2:
        {

            clearScreen();

            cout << "================================\n";
            cout << "         YOUR PASSWORD VAULT\n";
            cout << "================================\n";

            vault.displayAll();

            pauseScreen();
            break;
        }

        case 3:
        {

            string service;

            cout << "\nEnter service to search: ";
            getline(cin, service);

            vault.searchByService(service);

            pauseScreen();
            break;
        }

        case 4:
        {

            string service;

            cout << "\nEnter service to delete: ";
            getline(cin, service);

            vault.deleteEntry(service);

            pauseScreen();
            break;
        }

        case 5:
        {

            string service, username, password, category;

            cout << "\n===== EDIT ACCOUNT =====\n";

            cout << "Service to edit: ";
            getline(cin, service);

            cout << "New username: ";
            getline(cin, username);

            cout << "New password: ";
            getline(cin, password);

            cout << "New category: ";
            getline(cin, category);

            try
            {

                vault.editEntry(
                    service, username, password, category);
            }
            catch (const invalid_argument &e)
            {
                cout << "\n[VALIDATION ERROR] "
                     << e.what() << endl;
            }
            catch (const exception &e)
            {
                cout << "\n[ERROR] " << e.what() << endl;
            }

            pauseScreen();
            break;
        }

        case 6:
        {

            int length;

            cout << "\n===== PASSWORD GENERATOR =====\n";

            cout << "Enter password length (8-128): ";

            if (!(cin >> length))
            {

                cout << "\n[ERROR] Enter a valid number!\n";

                cin.clear();
                cin.ignore(
                    numeric_limits<streamsize>::max(), '\n');

                pauseScreen();
                break;
            }

            cin.ignore(
                numeric_limits<streamsize>::max(), '\n');

            bool uppercase = getYesNo("Include uppercase letters?");
            bool lowercase = getYesNo("Include lowercase letters?");
            bool numbers = getYesNo("Include numbers?");
            bool special = getYesNo("Include special characters?");

            try
            {

                string generatedPassword =
                    PasswordGenerator::generatePassword(
                        length,
                        uppercase,
                        lowercase,
                        numbers,
                        special);

                cout << "\n[SUCCESS] Password generated!\n";
                cout << "Generated password: "
                     << generatedPassword << endl;

                cout << "\nRemember to store it securely.\n";
            }
            catch (const invalid_argument &e)
            {

                cout << "\n[VALIDATION ERROR] "
                     << e.what() << endl;
            }
            catch (const exception &e)
            {

                cout << "\n[ERROR] " << e.what() << endl;
            }

            pauseScreen();
            break;
        }

        case 7:
        {

            string password;

            cout << "\n===== PASSWORD STRENGTH ANALYZER =====\n";

            cout << "Enter password to analyze: ";
            getline(cin, password);

            PasswordAnalysis result =
                PasswordAnalyzer::analyze(password);

            cout << "\n========== ANALYSIS RESULT ==========\n";

            cout << "Score    : " << result.score << "/100\n";
            cout << "Strength : " << result.strength << endl;

            if (result.suggestions.empty())
            {

                cout << "\nNo basic improvements suggested!\n";
            }
            else
            {

                cout << "\n===== SUGGESTIONS =====\n";

                for (const string &suggestion : result.suggestions)
                {
                    cout << "- " << suggestion << endl;
                }
            }

            cout << "====================================\n";

            pauseScreen();

            break;
        }

        case 8:
        {

            clearScreen();

            cout << "Thank you for using VaultX!\n";
            cout << "Exiting application...\n";

            return 0;
        }

        default:
        {

            cout << "\n[ERROR] Invalid choice! Select 1-8.\n";

            pauseScreen();
        }
        }
    }

    return 0;
}
