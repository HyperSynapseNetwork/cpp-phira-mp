cmake_minimum_required(VERSION 3.20)
project(phira-mp-server CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Boost – header-only (Asio + Beast)
find_package(Boost 1.74 REQUIRED)
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SPDLOG REQUIRED IMPORTED_TARGET spdlog)
pkg_check_modules(ARGON2 REQUIRED IMPORTED_TARGET libargon2)
find_package(nlohmann_json 3.0 REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)

add_executable(phira-mp-server
    src/main.cpp
    src/binary.cpp
    src/command.cpp
    src/stream.cpp
    src/l10n.cpp
    src/room.cpp
    src/session.cpp
    src/server.cpp
    src/http_server.cpp
    src/visitor_db.cpp
)

target_include_directories(phira-mp-server PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(phira-mp-server PRIVATE
    Boost::headers
    Threads::Threads
    CURL::libcurl
    OpenSSL::SSL OpenSSL::Crypto
    PkgConfig::SPDLOG
    PkgConfig::ARGON2
    nlohmann_json::nlohmann_json
    PkgConfig::SQLITE3
    uuid
)

target_compile_definitions(phira-mp-server PRIVATE
    LOCALES_DIR=${CMAKE_SOURCE_DIR}/locales
)

install(TARGETS phira-mp-server DESTINATION bin)
install(DIRECTORY locales/ DESTINATION share/phira-mp/locales)
