#pragma once
#include "stream.hpp"
#include <boost/beast.hpp>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <nlohmann/json.hpp>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;

class ServerState; // forward

// ── SSE connection (blocking, runs in its own thread) ─────────────────
class SseConnection : public std::enable_shared_from_this<SseConnection> {
public:
    SseConnection(tcp::socket sock);

    // Blocking: sends headers + initial_data, then loops waiting for events.
    // Returns only when the client disconnects or close() is called.
    void run(const std::string& initial_data);

    // Thread-safe: enqueue an event to be sent.
    void send_event(const std::string& event_type, const std::string& data);

    bool is_open() const;
    void close();

private:
    tcp::socket socket_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::queue<std::string> queue_;
    bool closed_ = false;
};

// ── SSE broadcaster ──────────────────────────────────────────────────
class SseBroadcaster {
public:
    void add(std::shared_ptr<SseConnection> conn);
    void broadcast(const std::string& event_type, const std::string& data);
private:
    std::mutex mu_;
    std::vector<std::shared_ptr<SseConnection>> connections_;
};

// ── HTTP server ──────────────────────────────────────────────────────
class HttpServer {
public:
    HttpServer(asio::io_context& ioc, uint16_t port,
               std::shared_ptr<ServerState> state,
               const std::string& admin_password);
    void start();
    SseBroadcaster& broadcaster() { return broadcaster_; }
private:
    void do_accept();
    void handle_request(tcp::socket sock);
    asio::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<ServerState> state_;
    std::string admin_password_;
    SseBroadcaster broadcaster_;
};

// ── Request router ───────────────────────────────────────────────────
class RequestHandler {
public:
    RequestHandler(std::shared_ptr<ServerState> state,
                   const std::string& admin_password,
                   SseBroadcaster& broadcaster);
    bool handle(http::request<http::string_body>& req,
                http::response<http::string_body>& res);
    bool is_sse_request(const http::request<http::string_body>& req) const;
    std::string get_sse_initial_data();
private:
    void handle_rooms_info(http::response<http::string_body>& res);
    void handle_room_by_name(const std::string& name, http::response<http::string_body>& res);
    void handle_room_by_user(int32_t user_id, http::response<http::string_body>& res);
    void handle_admin_page(http::response<http::string_body>& res);
    bool check_admin_auth(const http::request<http::string_body>& req);
    void handle_admin_create_room(const std::string& body, http::response<http::string_body>& res);
    void handle_admin_delete_room(const std::string& body, http::response<http::string_body>& res);
    void handle_admin_kick_user(const std::string& body, http::response<http::string_body>& res);
    void handle_admin_ban_user(const std::string& body, http::response<http::string_body>& res);
    void handle_admin_unban_user(const std::string& body, http::response<http::string_body>& res);
    void handle_admin_banned_list(http::response<http::string_body>& res);
    nlohmann::json room_data_to_json(const std::string& name, std::shared_ptr<class Room> room);
    std::shared_ptr<ServerState> state_;
    std::string admin_password_;
    SseBroadcaster& broadcaster_;
};

const char* get_admin_html();
