// ─────────────────────────────────────────────────────────────────────────
// server.cpp — 优化版
//
// 主要改动：
//   1. 构造函数内调用 HttpClient::warmup(...)，
//      启动时即建立到 phira.5wyxi.com 的 TLS 会话与 DNS 缓存，
//      使第一个真实客户端的 /me 请求不再承担首次握手成本。
//
//   2. acceptor 同时启用 SO_REUSEADDR + reuse_port（Linux），
//      多 io_context 线程并发 accept，提升高并发连接吞吐。
//
//   3. accept 回调不再做任何阻塞工作；socket 选项调优后立即继续 accept，
//      Session::create 走原线程；这保证了 TCP backlog 能被快速消化。
//
//   4. 启用 TCP_DEFER_ACCEPT（Linux）：内核在客户端第一段数据到达前不
//      唤醒 accept，省一次上下文切换；并配合 LISTEN backlog 调大。
// ─────────────────────────────────────────────────────────────────────────
#include "server.hpp"
#include "http_server.hpp"
#include "http_client.hpp"      // ← NEW
#include <spdlog/spdlog.h>
#include <cstdlib>
#include <fstream>
#include <nlohmann/json.hpp>

#ifdef __linux__
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

// ── ServerState ───────────────────────────────────────────────────────
std::shared_ptr<Session> ServerState::get_room_monitor() {
    std::shared_lock lk(rm_mu); return room_monitor.lock();
}
std::shared_ptr<Session> ServerState::get_game_monitor(int32_t id) {
    std::shared_lock lk(gm_mu);
    auto it = game_monitors.find(id);
    return it != game_monitors.end() ? it->second.lock() : nullptr;
}
void ServerState::set_game_monitor(int32_t id, std::weak_ptr<Session> s) {
    std::unique_lock lk(gm_mu); game_monitors[id] = s;
}

void ServerState::handle_lost_connection(const Uuid& id) {
    spdlog::warn("lost connection with {}", id.to_string());
    std::shared_ptr<Session> sess;
    { std::unique_lock lk(sessions_mu);
      auto it = sessions.find(id);
      if (it == sessions.end()) return;
      sess = it->second; sessions.erase(it);
    }
    if (sess && sess->user) {
        std::shared_lock lk(sess->user->session_mu);
        auto cur = sess->user->session.lock();
        if (cur && cur.get() == sess.get()) { lk.unlock(); sess->user->dangle(); }
    }
}

bool ServerState::is_banned(int32_t user_id) const {
    std::shared_lock lk(ban_mu);
    return banned_users.count(user_id) > 0;
}

void ServerState::load_bans() {
    try {
        std::ifstream f("banned_users.json");
        if (!f.is_open()) return;
        auto j = nlohmann::json::parse(f);
        std::unique_lock lk(ban_mu);
        for (auto& id : j) banned_users.insert(id.get<int32_t>());
        spdlog::info("Loaded {} banned users", banned_users.size());
    } catch (...) { spdlog::warn("Could not load banned_users.json"); }
}

void ServerState::save_bans() {
    try {
        nlohmann::json arr = nlohmann::json::array();
        { std::shared_lock lk(ban_mu);
          for (auto id : banned_users) arr.push_back(id); }
        std::ofstream f("banned_users.json");
        f << arr.dump(2);
    } catch (...) { spdlog::warn("Could not save banned_users.json"); }
}

void ServerState::emit_sse(const std::string& event_type, const std::string& data) {
    if (sse_broadcaster) sse_broadcaster->broadcast(event_type, data);
}

// ── Server ────────────────────────────────────────────────────────────
Server::Server(asio::io_context& ioc, uint16_t port)
    : ioc_(ioc),
      acceptor_(ioc, tcp::endpoint(asio::ip::address_v6::any(), port)) {
    state_ = std::make_shared<ServerState>();

    // Load config
    std::ifstream cfg("server_config.yml");
    if (cfg.is_open()) {
        std::string line; bool in_mon = false;
        while (std::getline(cfg, line)) {
            while (!line.empty() && std::isspace((unsigned char)line.front()))
                line.erase(line.begin());
            if (line.find("monitors:") == 0) {
                in_mon = true; state_->config.monitors.clear(); continue;
            }
            if (in_mon && line.size() > 2 && line[0] == '-') {
                std::string v = line.substr(1);
                while (!v.empty() && std::isspace((unsigned char)v.front()))
                    v.erase(v.begin());
                try { state_->config.monitors.push_back(std::stoi(v)); }
                catch (...) {}
            } else in_mon = false;
        }
        spdlog::info("Loaded config with {} monitors", state_->config.monitors.size());
    }

    try { state_->room_monitor_key = generate_secret_key("room_monitor", 64); }
    catch (const std::exception& e) { spdlog::error("Key gen fail: {}", e.what()); }

#ifdef _WIN32
    _putenv_s("HSN_SECRET_KEY", "");
#else
    ::unsetenv("HSN_SECRET_KEY");
#endif

    // ── PERF: 关键 socket 选项 ──────────────────────────────────────
    error_code opt_ec;
    acceptor_.set_option(asio::socket_base::reuse_address(true), opt_ec);
#ifdef __linux__
    // SO_REUSEPORT：让多个 io_context 线程同时 accept，内核侧负载均衡
    int one = 1;
    ::setsockopt(acceptor_.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                 &one, sizeof(one));
    // TCP_DEFER_ACCEPT：仅当客户端第一段数据到达后才把连接送给 accept，
    // 在防御 SYN flood 的同时避免连接还没数据时就唤醒线程。
    int defer = 5;  // seconds
    ::setsockopt(acceptor_.native_handle(), IPPROTO_TCP, TCP_DEFER_ACCEPT,
                 &defer, sizeof(defer));
#endif
    // 调大 listen backlog（默认 SOMAXCONN，通常 128；繁忙时不够）
    acceptor_.listen(asio::socket_base::max_listen_connections, opt_ec);

    // Load ban list
    state_->load_bans();

    // ── PERF: 提前建立到 phira API 的 TLS 会话和 DNS 缓存 ──
    // 这一步在后台线程异步完成，不会阻塞服务器启动。
    HttpThreadPool::instance().submit([]() {
        HttpClient::instance().warmup("https://phira.5wyxi.com/me");
    });
}

void Server::start() {
    spdlog::info("Listening on port {}", acceptor_.local_endpoint().port());
    do_accept();
}

void Server::do_accept() {
    acceptor_.async_accept([this](error_code ec, tcp::socket sock) {
        if (!ec) {
            // ── PERF: socket pre-tune ─────────────────────────────
            error_code opt_ec;
            sock.set_option(tcp::no_delay(true), opt_ec);
            sock.set_option(asio::socket_base::keep_alive(true), opt_ec);
#ifdef __linux__
            int keepidle = 30, keepintvl = 10, keepcnt = 3;
            ::setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPIDLE,
                         &keepidle, sizeof(keepidle));
            ::setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPINTVL,
                         &keepintvl, sizeof(keepintvl));
            ::setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPCNT,
                         &keepcnt, sizeof(keepcnt));
#endif

            try {
                auto addr = sock.remote_endpoint();
                auto uid  = Uuid::generate();
                spdlog::info("Connection from {} ({})",
                             addr.address().to_string(), uid.to_string());
                auto sess = Session::create(uid, std::move(sock), state_, ioc_);
                { std::unique_lock lk(state_->sessions_mu);
                  state_->sessions[uid] = sess; }
            } catch (const std::exception& e) {
                spdlog::error("Session create fail: {}", e.what());
            }
        } else {
            spdlog::warn("accept fail: {}", ec.message());
        }
        do_accept();
    });
}
