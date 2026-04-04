#pragma once
#include "session.hpp"
#include "visitor_db.hpp"
#include <fstream>
#include <set>
#include <unordered_map>

// Forward declaration
class SseBroadcaster;

struct ServerConfig {
    std::vector<int32_t> monitors = {2};
};

class ServerState : public std::enable_shared_from_this<ServerState> {
public:
    ServerConfig config;
    std::vector<uint8_t> room_monitor_key;

    mutable std::shared_mutex sessions_mu, users_mu, rooms_mu, rm_mu, gm_mu;
    std::unordered_map<Uuid, std::shared_ptr<Session>, UuidHash> sessions;
    std::map<int32_t, std::shared_ptr<User>> users;
    std::map<std::string, std::shared_ptr<Room>> rooms;
    std::weak_ptr<Session> room_monitor;
    std::map<int32_t, std::weak_ptr<Session>> game_monitors;

    // Ban system
    mutable std::shared_mutex ban_mu;
    std::set<int32_t> banned_users;

    // Visitor database
    VisitorDB visitor_db;

    // SSE broadcaster (set by main after creation)
    SseBroadcaster* sse_broadcaster = nullptr;

    std::shared_ptr<Session> get_room_monitor();
    std::shared_ptr<Session> get_game_monitor(int32_t id);
    void set_game_monitor(int32_t id, std::weak_ptr<Session> s);
    void handle_lost_connection(const Uuid& id);

    bool is_banned(int32_t user_id) const;
    void load_bans();
    void save_bans();

    // SSE event helpers
    void emit_sse(const std::string& event_type, const std::string& data);
};

class Server {
public:
    Server(asio::io_context& ioc, uint16_t port);
    void start();
    std::shared_ptr<ServerState> state() { return state_; }
private:
    void do_accept();
    asio::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<ServerState> state_;
};
