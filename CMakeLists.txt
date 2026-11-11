cmake_minimum_required(VERSION 3.16)
project(VaultX CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED)

# Web server (Crow is header-only and lives in third_party/Crow)
add_executable(vaultx_server
    src/server.cpp src/Entry.cpp src/EntryStore.cpp
    src/Database.cpp src/Crypto.cpp)

target_include_directories(vaultx_server PRIVATE
    include third_party/Crow/include ${ASIO_INCLUDE_DIR})

target_link_libraries(vaultx_server PRIVATE
    OpenSSL::Crypto SQLite::SQLite3 Threads::Threads)

if(WIN32)
    target_link_libraries(vaultx_server PRIVATE ws2_32 mswsock)
endif()
