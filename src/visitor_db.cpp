#include "visitor_db.hpp"
#include <spdlog/spdlog.h>

VisitorDB::~VisitorDB() { close(); }

bool VisitorDB::open(const std::string& path) {
    std::lock_guard lk(mu_);
    if (db_) return true;  // already open

    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to open visitor database '{}': {}", path, sqlite3_errmsg(db_));
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    // Create table if not exists
    const char* create_sql =
    "CREATE TABLE IF NOT EXISTS visited ("
    "  phira_id INTEGER PRIMARY KEY"
    ");";
    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to create visited table: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    // Prepare the insert statement
    const char* insert_sql = "INSERT INTO visited (phira_id) VALUES (?);";
    rc = sqlite3_prepare_v2(db_, insert_sql, -1, &insert_stmt_, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare insert statement: {}", sqlite3_errmsg(db_));
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    spdlog::info("Visitor database opened: {}", path);
    return true;
}

bool VisitorDB::record_visit(int32_t user_id) {
    std::lock_guard lk(mu_);
    if (!db_ || !insert_stmt_) return false;

    sqlite3_reset(insert_stmt_);
    sqlite3_bind_int(insert_stmt_, 1, user_id);

    int rc = sqlite3_step(insert_stmt_);
    if (rc == SQLITE_DONE) {
        spdlog::info("New visitor recorded: user {}", user_id);
        return true;
    } else if (rc == SQLITE_CONSTRAINT) {
        // PRIMARY KEY constraint = user already exists (the "rowid as rowid" scenario)
        spdlog::info("Visitor already exists: user {}", user_id);
        return false;
    } else {
        spdlog::warn("Failed to record visitor {}: {}", user_id, sqlite3_errmsg(db_));
        return false;
    }
}

void VisitorDB::close() {
    std::lock_guard lk(mu_);
    if (insert_stmt_) { sqlite3_finalize(insert_stmt_); insert_stmt_ = nullptr; }
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}
