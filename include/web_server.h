#pragma once
#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <functional>
#include <set>
#include <shared_mutex>

struct ServerState; // forward

class WebServer {
public:
    explicit WebServer(uint16_t port, std::shared_ptr<ServerState> state);
    ~WebServer();

    void start();
    void stop();

    // SSE event broadcasting
    void broadcast_sse(const std::string& event_type, const std::string& json_data);

private:
    uint16_t port_;
    int listen_fd_ = -1;
    std::shared_ptr<ServerState> state_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    std::thread sse_heartbeat_thread_;

    // SSE clients
    mutable std::mutex sse_mtx_;
    std::vector<int> sse_clients_;

    // Admin password management
    mutable std::shared_mutex password_mtx_;
    std::string admin_password_;
    std::string password_file_ = "admin_password.txt";

    // Session tokens (simple in-memory token store)
    mutable std::mutex token_mtx_;
    std::set<std::string> valid_tokens_;

    void accept_loop();
    void handle_client(int client_fd);
    void sse_heartbeat_loop();

    // Password management
    void load_password();
    void save_password();
    bool check_password(const std::string& password) const;
    bool set_password(const std::string& old_pass, const std::string& new_pass);
    std::string generate_token();
    bool validate_token(const std::string& token) const;
    void add_token(const std::string& token);
    void remove_token(const std::string& token);
    std::string extract_cookie_token(const std::string& headers) const;
    bool is_password_set() const;

    // HTTP helpers
    struct HttpRequest {
        std::string method;
        std::string path;
        std::string body;
        std::string query;
        std::string headers_raw;   // full headers for cookie extraction
    };

    HttpRequest parse_request(int fd);
    void send_response(int fd, int status, const std::string& content_type,
                       const std::string& body,
                       const std::string& extra_headers = "");
    void send_sse_headers(int fd);

    // Route handlers
    void handle_api_rooms_info(int fd);
    void handle_api_room_info(int fd, const std::string& name);
    void handle_api_room_user(int fd, int32_t user_id);
    void handle_api_rooms_listen(int fd);
    void handle_admin_page(int fd, const std::string& token);
    void handle_admin_login_page(int fd);
    void handle_admin_login(int fd, const std::string& body);
    void handle_admin_logout(int fd);
    void handle_admin_change_password(int fd, const std::string& body);
    void handle_admin_api_rooms(int fd);
    void handle_admin_api_bans(int fd);
    void handle_admin_dissolve(int fd, const std::string& body);
    void handle_admin_ban(int fd, const std::string& body);
    void handle_admin_unban(int fd, const std::string& body);
    void handle_admin_kick(int fd, const std::string& body);

    // JSON builders
    std::string room_to_json(const std::string& room_name) const;
    std::string record_to_json(const struct Record& rec) const;
    std::string all_rooms_json() const;
};

// Global web server pointer for SSE broadcasting from room events
extern WebServer* g_web_server;
