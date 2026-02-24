#pragma once
#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <shared_mutex>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct ServerState; // forward
struct Room;        // forward

// ── Global TLS certificate paths ──────────────────────────────────────
extern std::string g_tls_cert_path;
extern std::string g_tls_key_path;

// ── WebSocket client connection ───────────────────────────────────────
struct WsClient {
    int fd = -1;
    SSL* ssl = nullptr;
    std::string room_id;
    int32_t player_id = 0;
    std::atomic<bool> alive{true};
    std::mutex write_mtx;  // protects SSL_write

    ~WsClient();
    bool send_text(const std::string& data);
    void close_connection();
};

// ── WebSocket Secure Server ───────────────────────────────────────────
class WsServer {
public:
    explicit WsServer(uint16_t port, std::shared_ptr<ServerState> state);
    ~WsServer();

    void start();
    void stop();

    // Called from session.cpp when touch/judge data arrives
    void broadcast_touches(const std::string& room_id, int32_t player_id,
                           const std::string& json_data);
    void broadcast_judges(const std::string& room_id, int32_t player_id,
                          const std::string& json_data);

    // WebSocket framing (public for WsClient access)
    static std::vector<uint8_t> make_ws_frame(const std::string& payload, uint8_t opcode = 0x01);

private:
    uint16_t port_;
    int listen_fd_ = -1;
    SSL_CTX* ssl_ctx_ = nullptr;
    std::shared_ptr<ServerState> state_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;

    // Connected WS clients
    mutable std::shared_mutex clients_mtx_;
    std::vector<std::shared_ptr<WsClient>> clients_;

    bool init_ssl();
    void accept_loop();
    void handle_client(int client_fd);
    bool do_ws_handshake(SSL* ssl, std::string& room_id, int32_t& player_id);

    // WebSocket framing
    static bool read_ws_frame(SSL* ssl, std::string& payload, uint8_t& opcode);

    // Send to matching subscribers
    void send_to_subscribers(const std::string& room_id, int32_t player_id,
                             const std::string& event_type, const std::string& json_data);

    void cleanup_dead_clients();
};

// Global WS server pointer
extern WsServer* g_ws_server;
