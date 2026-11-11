// Web entry point: wires the objects together and starts the HTTP server.
#include <cstdlib>
#include <iostream>

#include "ApiServer.h"
#include "Crypto.h"
#include "Database.h"
#include "PasswordVault.h"

using namespace std;

int main() {
    try {
        const char* path = std::getenv("VAULTX_DB");

        Database database(path ? path : "vaultx.db");  // is-a Storage
        database.createTables();                       // fresh installs have no tables yet

        AesGcmCipher cipher;                           // is-a Cipher
        PasswordVault vault(database, cipher);         // depends on the interfaces only

        ApiServer server(vault);
        server.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal server error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
