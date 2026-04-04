#pragma once
#include <string>
#include <mutex>
#include <sqlite3.h>

class VisitorDB {
public:
    VisitorDB() = default;
    ~VisitorDB();

    // Open/create the database at the given path, create table if needed
    bool open(const std::string& path);

    // Record a visitor; returns true if newly inserted, false if already existed
    bool record_visit(int32_t user_id);

    // Close the database
    void close();

private:
    sqlite3* db_ = nullptr;
    sqlite3_stmt* insert_stmt_ = nullptr;
    std::mutex mu_;
};
