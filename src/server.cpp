#include "server.hpp"
#include "http_server.hpp"
#include <spdlog/spdlog.h>
#include <cstdlib>
#include <fstream>
#include <nlohmann/json.hpp>

#ifdef __linux__
#include <netinet/tcp.h>
#endif

// ── ServerState ───────────────────────────────────────────────────────
std::shared_ptr<Session> ServerState::get_room_monitor() { std::shared_lock lk(rm_mu); return room_monitor.lock(); }
std::shared_ptr<Session> ServerState::get_game_monitor(int32_t id) { std::shared_lock lk(gm_mu); auto it = game_monitors.find(id); return it != game_monitors.end() ? it->second.lock() : nullptr; }
void ServerState::set_game_monitor(int32_t id, std::weak_ptr<Session> s) { std::unique_lock lk(gm_mu); game_monitors[id] = s; }

void ServerState::handle_lost_connection(const Uuid& id) {
    spdlog::warn("lost connection with {}", id.to_string());
    std::shared_ptr<Session> sess;
    { std::unique_lock lk(sessions_mu); auto it = sessions.find(id); if (it == sessions.end()) return; sess = it->second; sessions.erase(it); }
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
    : ioc_(ioc), acceptor_(ioc, tcp::endpoint(asio::ip::address_v6::any(), port)) {
    state_ = std::make_shared<ServerState>();
    // Load config
    std::ifstream cfg("server_config.yml");
    if (cfg.is_open()) {
        std::string line; bool in_mon = false;
        while (std::getline(cfg, line)) {
            while (!line.empty() && std::isspace((unsigned char)line.front())) line.erase(line.begin());
            if (line.find("monitors:") == 0) { in_mon = true; state_->config.monitors.clear(); continue; }
            if (in_mon && line.size() > 2 && line[0] == '-') {
                std::string v = line.substr(1);
                while (!v.empty() && std::isspace((unsigned char)v.front())) v.erase(v.begin());
                try { state_->config.monitors.push_back(std::stoi(v)); } catch (...) {}
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
    acceptor_.set_option(asio::socket_base::reuse_address(true));

    // Load ban list
    state_->load_bans();
}

void Server::start() { spdlog::info("Listening on port {}", acceptor_.local_endpoint().port()); do_accept(); }

void Server::do_accept() {
    acceptor_.async_accept([this](error_code ec, tcp::socket sock) {
        if (!ec) {
            // ── PERF: Pre-tune socket before handing to Session ──────
            error_code opt_ec;
            sock.set_option(tcp::no_delay(true), opt_ec);                     // disable Nagle
            sock.set_option(asio::socket_base::keep_alive(true), opt_ec);     // detect dead peers
#ifdef __linux__
            // Reduce TCP keepalive timers for faster dead-peer detection
            int keepidle = 30;   // seconds before first keepalive probe
            int keepintvl = 10;  // seconds between probes
            int keepcnt = 3;     // probes before giving up
            ::setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
            ::setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
            ::setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
#endif

            auto addr = sock.remote_endpoint(); auto uid = Uuid::generate();
            spdlog::info("Connection from {} ({})", addr.address().to_string(), uid.to_string());
            try {
                auto sess = Session::create(uid, std::move(sock), state_, ioc_);
                { std::unique_lock lk(state_->sessions_mu); state_->sessions[uid] = sess; }
            } catch (const std::exception& e) { spdlog::error("Session create fail: {}", e.what()); }
        } else spdlog::warn("accept fail: {}", ec.message());
        do_accept();
    });
}
