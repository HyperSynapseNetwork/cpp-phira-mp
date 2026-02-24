#include "ws_server.h"
#include "server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// ── Globals ─────────────────────────────────────────────────────────
std::string g_tls_cert_path = "/etc/ssl/certs/server.crt";
std::string g_tls_key_path  = "/etc/ssl/private/server.key";
WsServer* g_ws_server = nullptr;

// ── Base64 encode ───────────────────────────────────────────────────
static std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

// ── WsClient ────────────────────────────────────────────────────────
WsClient::~WsClient() {
    close_connection();
}

void WsClient::close_connection() {
    alive.store(false);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (fd >= 0) {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
        fd = -1;
    }
}

bool WsClient::send_text(const std::string& data) {
    if (!alive.load() || !ssl) return false;
    auto frame = WsServer::make_ws_frame(data, 0x01);
    std::lock_guard<std::mutex> lock(write_mtx);
    int written = SSL_write(ssl, frame.data(), (int)frame.size());
    if (written <= 0) {
        alive.store(false);
        return false;
    }
    return true;
}

// ── WsServer ────────────────────────────────────────────────────────

WsServer::WsServer(uint16_t port, std::shared_ptr<ServerState> state)
    : port_(port), state_(std::move(state)) {}

WsServer::~WsServer() {
    stop();
}

bool WsServer::init_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD* method = TLS_server_method();
    ssl_ctx_ = SSL_CTX_new(method);
    if (!ssl_ctx_) {
        std::cerr << "[wss] failed to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Set minimum TLS version
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ssl_ctx_, g_tls_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[wss] failed to load certificate: " << g_tls_cert_path << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, g_tls_key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[wss] failed to load private key: " << g_tls_key_path << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!SSL_CTX_check_private_key(ssl_ctx_)) {
        std::cerr << "[wss] private key does not match certificate" << std::endl;
        return false;
    }

    std::cerr << "[wss] SSL initialized, cert=" << g_tls_cert_path
              << " key=" << g_tls_key_path << std::endl;
    return true;
}

void WsServer::start() {
    if (!init_ssl()) {
        std::cerr << "[wss] SSL init failed, WSS server will not start" << std::endl;
        return;
    }

    listen_fd_ = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "[wss] socket failed: " << strerror(errno) << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int v6only = 0;
    setsockopt(listen_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    struct sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port_);
    addr.sin6_addr = in6addr_any;

    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[wss] bind failed: " << strerror(errno) << std::endl;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return;
    }

    if (listen(listen_fd_, 32) < 0) {
        std::cerr << "[wss] listen failed: " << strerror(errno) << std::endl;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return;
    }

    running_.store(true);
    accept_thread_ = std::thread(&WsServer::accept_loop, this);

    std::cerr << "[wss] WebSocket Secure server listening on [::]:" << port_ << std::endl;
}

void WsServer::stop() {
    running_.store(false);
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    {
        std::unique_lock lock(clients_mtx_);
        for (auto& c : clients_) {
            c->close_connection();
        }
        clients_.clear();
    }
    if (accept_thread_.joinable()) accept_thread_.join();
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
}

void WsServer::accept_loop() {
    while (running_.load()) {
        struct pollfd pfd;
        pfd.fd = listen_fd_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 500);
        if (ret <= 0) continue;

        struct sockaddr_in6 client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(listen_fd_, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) continue;

        int flag = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        std::thread([this, client_fd]() {
            handle_client(client_fd);
        }).detach();
    }
}

void WsServer::handle_client(int client_fd) {
    // TLS handshake
    SSL* ssl = SSL_new(ssl_ctx_);
    if (!ssl) {
        ::close(client_fd);
        return;
    }
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "[wss] TLS handshake failed" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ::close(client_fd);
        return;
    }

    // WebSocket handshake
    std::string room_id;
    int32_t player_id = 0;
    if (!do_ws_handshake(ssl, room_id, player_id)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(client_fd);
        return;
    }

    // Validate room and player exist
    {
        std::shared_lock lock(state_->rooms_mtx);
        auto it = state_->rooms.find(room_id);
        if (it == state_->rooms.end()) {
            std::cerr << "[wss] room not found: " << room_id << std::endl;
            // Send close frame
            auto close_frame = make_ws_frame("room not found", 0x08);
            SSL_write(ssl, close_frame.data(), (int)close_frame.size());
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ::close(client_fd);
            return;
        }
    }

    std::cerr << "[wss] client subscribed: room=" << room_id
              << " player=" << player_id << std::endl;

    // Create client and add to list
    auto client = std::make_shared<WsClient>();
    client->fd = client_fd;
    client->ssl = ssl;
    client->room_id = room_id;
    client->player_id = player_id;

    {
        std::unique_lock lock(clients_mtx_);
        clients_.push_back(client);
    }

    // Send confirmation message
    client->send_text("{\"type\":\"connected\",\"room\":\"" + room_id +
                      "\",\"player\":" + std::to_string(player_id) + "}");

    // Read loop - handle pings and detect disconnect
    while (client->alive.load() && running_.load()) {
        std::string payload;
        uint8_t opcode;
        if (!read_ws_frame(ssl, payload, opcode)) {
            break;  // Connection lost
        }

        switch (opcode) {
        case 0x08:  // Close
            client->alive.store(false);
            break;
        case 0x09: {  // Ping → send Pong
            auto pong = make_ws_frame(payload, 0x0A);
            std::lock_guard<std::mutex> wl(client->write_mtx);
            SSL_write(ssl, pong.data(), (int)pong.size());
            break;
        }
        case 0x0A:  // Pong - ignore
            break;
        default:
            // Ignore text/binary from client
            break;
        }
    }

    std::cerr << "[wss] client disconnected: room=" << room_id
              << " player=" << player_id << std::endl;

    client->close_connection();
    cleanup_dead_clients();
}

bool WsServer::do_ws_handshake(SSL* ssl, std::string& room_id, int32_t& player_id) {
    // Read HTTP upgrade request
    char buf[4096];
    std::string raw;

    // Set a read timeout via poll on the underlying fd
    int fd = SSL_get_fd(ssl);

    while (raw.find("\r\n\r\n") == std::string::npos && raw.size() < 4096) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 5000) <= 0) return false;

        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n <= 0) return false;
        raw.append(buf, n);
    }

    // Parse request line: GET /room_id/player_id HTTP/1.1
    auto first_end = raw.find("\r\n");
    if (first_end == std::string::npos) return false;
    std::string first_line = raw.substr(0, first_end);

    std::string method, path, version;
    std::istringstream iss(first_line);
    iss >> method >> path >> version;

    if (method != "GET") return false;

    // Parse path: /room_id/player_id
    if (path.empty() || path[0] != '/') return false;
    path = path.substr(1);  // Remove leading /

    auto slash = path.find('/');
    if (slash == std::string::npos) return false;

    room_id = path.substr(0, slash);
    std::string pid_str = path.substr(slash + 1);

    // Remove trailing / or query string
    auto q = pid_str.find('?');
    if (q != std::string::npos) pid_str = pid_str.substr(0, q);
    auto tr = pid_str.find('/');
    if (tr != std::string::npos) pid_str = pid_str.substr(0, tr);

    try {
        player_id = std::stoi(pid_str);
    } catch (...) {
        return false;
    }

    if (room_id.empty() || player_id <= 0) return false;

    // Extract Sec-WebSocket-Key
    std::string ws_key;
    std::string key_search = "Sec-WebSocket-Key:";
    auto key_pos = raw.find(key_search);
    if (key_pos == std::string::npos) {
        key_search = "sec-websocket-key:";
        key_pos = raw.find(key_search);
    }
    if (key_pos == std::string::npos) return false;

    size_t key_start = key_pos + key_search.size();
    while (key_start < raw.size() && raw[key_start] == ' ') key_start++;
    auto key_end = raw.find("\r\n", key_start);
    if (key_end == std::string::npos) return false;
    ws_key = raw.substr(key_start, key_end - key_start);

    // Trim trailing spaces
    while (!ws_key.empty() && ws_key.back() == ' ') ws_key.pop_back();

    // Compute accept key: SHA-1(key + magic) → base64
    static const std::string WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string concat = ws_key + WS_MAGIC;
    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(concat.c_str()), concat.size(), sha1);
    std::string accept_key = base64_encode(sha1, SHA_DIGEST_LENGTH);

    // Send upgrade response
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept_key + "\r\n"
        "\r\n";

    if (SSL_write(ssl, response.c_str(), (int)response.size()) <= 0) return false;

    return true;
}

// ── WebSocket Frame Construction ──────────────────────────────────────
std::vector<uint8_t> WsServer::make_ws_frame(const std::string& payload, uint8_t opcode) {
    std::vector<uint8_t> frame;
    frame.push_back(0x80 | opcode);  // FIN + opcode

    size_t len = payload.size();
    if (len < 126) {
        frame.push_back((uint8_t)len);
    } else if (len < 65536) {
        frame.push_back(126);
        frame.push_back((uint8_t)(len >> 8));
        frame.push_back((uint8_t)(len & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--) {
            frame.push_back((uint8_t)((len >> (i * 8)) & 0xFF));
        }
    }

    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

// ── WebSocket Frame Reading ───────────────────────────────────────────
bool WsServer::read_ws_frame(SSL* ssl, std::string& payload, uint8_t& opcode) {
    int fd = SSL_get_fd(ssl);

    auto ssl_read_exact = [&](void* buf, int n) -> bool {
        int got = 0;
        while (got < n) {
            // Poll for readability with 30s timeout
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            if (poll(&pfd, 1, 30000) <= 0) return false;

            int r = SSL_read(ssl, (char*)buf + got, n - got);
            if (r <= 0) return false;
            got += r;
        }
        return true;
    };

    uint8_t header[2];
    if (!ssl_read_exact(header, 2)) return false;

    opcode = header[0] & 0x0F;
    bool masked = (header[1] & 0x80) != 0;
    uint64_t len = header[1] & 0x7F;

    if (len == 126) {
        uint8_t ext[2];
        if (!ssl_read_exact(ext, 2)) return false;
        len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (len == 127) {
        uint8_t ext[8];
        if (!ssl_read_exact(ext, 8)) return false;
        len = 0;
        for (int i = 0; i < 8; i++) {
            len = (len << 8) | ext[i];
        }
    }

    if (len > 1024 * 1024) return false;  // 1MB max

    uint8_t mask_key[4] = {0};
    if (masked) {
        if (!ssl_read_exact(mask_key, 4)) return false;
    }

    payload.resize(len);
    if (len > 0) {
        if (!ssl_read_exact(&payload[0], (int)len)) return false;
        if (masked) {
            for (size_t i = 0; i < len; i++) {
                payload[i] ^= mask_key[i % 4];
            }
        }
    }

    return true;
}

// ── Broadcasting ────────────────────────────────────────────────────
void WsServer::send_to_subscribers(const std::string& room_id, int32_t player_id,
                                    const std::string& event_type, const std::string& json_data) {
    std::string msg = "{\"type\":\"" + event_type + "\",\"room\":\"" + room_id +
                      "\",\"player\":" + std::to_string(player_id) +
                      ",\"data\":" + json_data + "}";

    std::shared_lock lock(clients_mtx_);
    for (auto& client : clients_) {
        if (client->alive.load() &&
            client->room_id == room_id &&
            client->player_id == player_id) {
            client->send_text(msg);
        }
    }
}

void WsServer::broadcast_touches(const std::string& room_id, int32_t player_id,
                                  const std::string& json_data) {
    send_to_subscribers(room_id, player_id, "touch_frame", json_data);
}

void WsServer::broadcast_judges(const std::string& room_id, int32_t player_id,
                                 const std::string& json_data) {
    send_to_subscribers(room_id, player_id, "judge_event", json_data);
}

void WsServer::cleanup_dead_clients() {
    std::unique_lock lock(clients_mtx_);
    clients_.erase(
        std::remove_if(clients_.begin(), clients_.end(),
                       [](auto& c) { return !c->alive.load(); }),
        clients_.end());
}
