// Console entry point (same vault and database as the website).
#include <cstdlib>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "Crypto.h"
#include "Database.h"
#include "DatabaseLocation.h"
#include "EntryTypes.h"
#include "Errors.h"
#include "PasswordGenerator.h"
#include "PasswordVault.h"
#include "SecureMemory.h"

using namespace std;

class ConsoleApp {
    PasswordVault& vault_;

    static string ask(const string& prompt) {
        cout << prompt << flush;
        string line;
        if (!getline(cin, line)) throw runtime_error("Input closed.");
        return line;
    }

    static string askHidden(const string& prompt) {
        cout << prompt << flush;
        string text;
#ifdef _WIN32
        int c;
        while ((c = _getch()) != '\r' && c != '\n') {
            if (c == 8) { if (!text.empty()) text.pop_back(); }
            else if (c >= 32) text.push_back(static_cast<char>(c));
        }
        cout << '\n';
#else
        termios saved{};
        bool tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved) == 0;

        if (tty) {
            termios hidden = saved;
            hidden.c_lflag &= ~ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &hidden);
        }

        bool ok = static_cast<bool>(getline(cin, text));

        if (tty) {
            tcsetattr(STDIN_FILENO, TCSANOW, &saved);
            cout << '\n';
        }

        if (!ok) throw runtime_error("Input closed.");
#endif
        return text;
    }

    static bool yes(const string& prompt) {
        string a = ask(prompt + " (y/N): ");
        return !a.empty() && (a[0] == 'y' || a[0] == 'Y');
    }

    bool login() {
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                if (!vault_.isInitialized()) {
                    cout << "No vault found. Let's create one (10+ characters).\n";
                    string first = askHidden("New master password: ");
                    StringWiper wipeFirst(first);  // erased when this block ends
                    string again = askHidden("Confirm master password: ");
                    StringWiper wipeAgain(again);

                    if (first != again) {
                        cout << "Passwords do not match.\n";
                        continue;
                    }
                    vault_.unlock(first);
                } else {
                    string password = askHidden("Master password: ");
                    StringWiper wipePassword(password);
                    vault_.unlock(password);
                }
                return true;
            } catch (const ApiError& e) {
                cout << "Error: " << e.what() << "\n";
            }
        }
        return false;
    }

    void list() {
        int shown = 0;

        for (const auto& e : vault_.list()) {
            if (e->deleted()) continue;

            cout << "  [" << e->id() << "] " << e->type() << " - " << e->title();
            if (!e->subtitle().empty()) cout << " (" << e->subtitle() << ")";
            if (!e->hint().empty()) cout << "  " << e->hint();
            cout << "  {" << e->folder() << "}\n";
            shown++;
        }

        if (!shown) cout << "  (no items yet)\n";
    }

    void view() {
        const Entry& e = vault_.get(stoi(ask("Item id: ")));
        bool reveal = yes("Reveal secret values?");

        cout << "\n" << e.type() << ": " << e.title() << "  {" << e.folder() << "}\n";

        for (const FieldSpec& spec : e.specs()) {          // polymorphic: each type has its own fields
            string value = e.field(spec.key);
            if (value.empty()) continue;
            cout << "  " << spec.label << ": " << (spec.secret && !reveal ? "••••••••" : value) << "\n";
        }

        if (!e.notes().empty()) cout << "  Notes: " << e.notes() << "\n";
    }

    void add() {
        vector<string> types = EntryFactory::types();

        for (size_t i = 0; i < types.size(); i++) cout << "  " << i + 1 << ") " << types[i] << "\n";

        size_t choice = stoul(ask("Type: "));
        if (choice < 1 || choice > types.size()) throw ApiError(400, "Unknown item type.");

        unique_ptr<Entry> entry = EntryFactory::create(types[choice - 1]);  // factory

        entry->setTitle(ask("Title: "));
        entry->setFolder(ask("Folder (Personal/Work/Finance/Social) [Personal]: "));

        for (const FieldSpec& spec : entry->specs()) {
            string label = spec.label + (spec.required ? " *" : "") + ": ";
            entry->setField(spec.key, spec.secret ? askHidden(label) : ask(label));
        }

        if (entry->notesRequired() || yes("Add notes?"))
            entry->setNotes(ask(entry->notesRequired() ? "Note content *: " : "Notes: "));

        const Entry& saved = vault_.add(std::move(entry));  // validates polymorphically
        cout << "Saved as item " << saved.id() << ".\n";
    }

    void generate() {
        GeneratorOptions options;
        string answer = ask("Length (8-128) [20]: ");

        if (!answer.empty()) options.length = stoul(answer);

        if (options.length < 8 || options.length > 128) {
            cout << "Length must be between 8 and 128.\n";
            return;
        }

        cout << PasswordGenerator::generate(options) << "\n";
    }

    void changeMaster() {
        string current = askHidden("Current master password: ");
        StringWiper wipeCurrent(current);
        string next = askHidden("New master password: ");
        StringWiper wipeNext(next);
        string again = askHidden("Confirm new master password: ");
        StringWiper wipeAgain(again);

        if (next != again) {
            cout << "Passwords do not match.\n";
            return;
        }

        vault_.changePassword(current, next);
        cout << "Master password changed; vault re-encrypted.\n";
    }

public:
    explicit ConsoleApp(PasswordVault& vault) : vault_(vault) {}

    void run() {
        cout << "\n=== VaultX ===\n";

        if (!login()) return;

        while (true) {
            cout << "\n1) List  2) View  3) Add  4) Delete  5) Generate password  "
                    "6) Change master password  0) Lock & exit\n";

            string choice = ask("> ");

            try {
                if (choice == "1") list();
                else if (choice == "2") view();
                else if (choice == "3") add();
                else if (choice == "4") {
                    int id = stoi(ask("Item id: "));
                    if (yes("Delete permanently?")) { vault_.remove(id); cout << "Deleted.\n"; }
                }
                else if (choice == "5") generate();
                else if (choice == "6") changeMaster();
                else if (choice == "0") break;
                else cout << "Unknown option.\n";
            }
            catch (const ApiError& e) { cout << "Error: " << e.what() << "\n"; }
            catch (const logic_error&) { cout << "Please enter a valid number.\n"; }
        }

        vault_.lock();
        cout << "Vault locked. Goodbye!\n";
    }
};

int main() {
    try {
        DatabaseLocation::Result location = DatabaseLocation::resolve();
        if (!location.notice.empty()) cerr << "Notice: " << location.notice << "\n";

        Database database(location.path);
        database.createTables();

        AesGcmCipher cipher;
        PasswordVault vault(database, cipher);

        // Opt-in: upgrade old records to the id-bound format at every unlock.
        const char* upgrade = getenv("VAULTX_UPGRADE_RECORDS");
        vault.setAutoUpgrade(upgrade != nullptr && string(upgrade) == "1");

        ConsoleApp(vault).run();
    }
    catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
