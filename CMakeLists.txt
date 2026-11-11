cmake_minimum_required(VERSION 3.16)
project(VaultX CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED)

# Everything except the two entry points lives in one static library.
add_library(vaultx_core STATIC
    src/Crypto.cpp
    src/Database.cpp
    src/DatabaseLocation.cpp
    src/Entry.cpp
    src/EntryTypes.cpp
    src/PasswordVault.cpp
    src/PasswordAnalyzer.cpp
    src/PasswordGenerator.cpp
    src/ApiServer.cpp)

target_include_directories(vaultx_core PUBLIC
    include third_party/Crow/include ${ASIO_INCLUDE_DIR})

target_link_libraries(vaultx_core PUBLIC
    OpenSSL::Crypto SQLite::SQLite3 Threads::Threads)

if(WIN32)
    target_link_libraries(vaultx_core PUBLIC ws2_32 mswsock)
endif()

add_executable(vaultx_server src/server.cpp)   # website + API
target_link_libraries(vaultx_server PRIVATE vaultx_core)

add_executable(vaultx_cli src/main.cpp)        # console version
target_link_libraries(vaultx_cli PRIVATE vaultx_core)
