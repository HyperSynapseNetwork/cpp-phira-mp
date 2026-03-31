#pragma once
#include "room.hpp"
#include "stream.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <shared_mutex>

class ServerState;

class User : public std::enable_shared_from_this<User> {
public:
    User(int32_t id, const std::string& name, Lang lang,
         std::shared_ptr<ServerState> srv, asio::io_context& ioc);
    UserInfo to_info() const;
    bool can_monitor() const;
    void set_session(std::weak_ptr<class Session> s);
    void try_send(const ServerCommand& cmd);
    void dangle();

    int32_t id; std::string name; Lang lang;
    std::shared_ptr<ServerState> server;
    asio::io_context& ioc;                           // ← NEW
    mutable std::shared_mutex session_mu, room_mu;
    std::weak_ptr<class Session> session;
    std::shared_ptr<Room> room;
    std::atomic<bool> monitor{false}, console{false};
    std::atomic<uint32_t> game_time{0};
    std::mutex dangle_mu;
    std::shared_ptr<int> dangle_mark;
    std::shared_ptr<asio::steady_timer> dangle_timer; // ← NEW: replaces detached thread
};

enum class SessionCategory { Normal, Console, RoomMonitor, GameMonitor };

class Session : public std::enable_shared_from_this<Session> {
public:
    static std::shared_ptr<Session> create(Uuid id, tcp::socket sock,
                                           std::shared_ptr<ServerState> srv, asio::io_context& ioc);
    void try_send(const ServerCommand& cmd);
    uint8_t version() const;

    Uuid id;
    SessionCategory category = SessionCategory::Normal;
    std::shared_ptr<User> user;

private:
    Session(Uuid id, std::shared_ptr<ServerState> srv, asio::io_context& ioc);
    void on_recv(ClientCommand cmd);
    void on_error(const std::string& err);
    void handle_auth(const ClientCommand& cmd);
    std::optional<ServerCommand> process(const ClientCommand& cmd);
    void start_heartbeat();

    std::shared_ptr<ServerState> server_;
    std::shared_ptr<TcpBinaryStream> stream_;
    asio::io_context& ioc_;
    std::mutex last_recv_mu_;
    std::chrono::steady_clock::time_point last_recv_;
    std::atomic<bool> waiting_auth_{true}, panicked_{false};
    std::shared_ptr<asio::steady_timer> hb_timer_;
};
