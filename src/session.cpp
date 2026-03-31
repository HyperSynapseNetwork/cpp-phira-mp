#include "session.hpp"
#include "server.hpp"
#include <spdlog/spdlog.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <cstring>

static const std::string PHIRA_HOST = "https://phira.5wyxi.com";

// ── CURL helper ───────────────────────────────────────────────────────
static size_t curl_cb(void* p, size_t sz, size_t nm, std::string* o) { o->append((char*)p, sz*nm); return sz*nm; }
static std::string http_get(const std::string& url, const std::string& auth = "") {
    CURL* c = curl_easy_init(); if (!c) throw std::runtime_error("CURL init fail");
    std::string resp;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    struct curl_slist* hdrs = nullptr;
    if (!auth.empty()) { hdrs = curl_slist_append(hdrs, ("Authorization: " + auth).c_str()); curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs); }
    CURLcode rc = curl_easy_perform(c); long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (hdrs) curl_slist_free_all(hdrs); curl_easy_cleanup(c);
    if (rc != CURLE_OK) throw std::runtime_error(std::string("HTTP fail: ") + curl_easy_strerror(rc));
    if (code >= 400) throw std::runtime_error("HTTP " + std::to_string(code));
    return resp;
}

struct AuthResult { int32_t id; std::string name, language; };
static AuthResult authenticate_http(const std::string& token) {
    if (token.size() > 32) throw std::runtime_error("invalid token length");
    auto body = http_get(PHIRA_HOST + "/me", "Bearer " + token);
    auto j = nlohmann::json::parse(body);
    return { j.at("id").get<int32_t>(), j.at("name").get<std::string>(), j.value("language", "en-US") };
}

// ── User ──────────────────────────────────────────────────────────────
User::User(int32_t id, const std::string& name, Lang lang,
           std::shared_ptr<ServerState> srv, asio::io_context& ioc)
    : id(id), name(name), lang(lang), server(std::move(srv)), ioc(ioc) {}

UserInfo User::to_info() const { return {id, name, monitor.load(std::memory_order_seq_cst)}; }
bool User::can_monitor() const { for (auto m : server->config.monitors) if (m == id) return true; return false; }
void User::set_session(std::weak_ptr<Session> s) {
    { std::unique_lock lk(session_mu); session = s; }
    { std::lock_guard lk(dangle_mu); dangle_mark.reset(); if (dangle_timer) { dangle_timer->cancel(); dangle_timer.reset(); } }
}
void User::try_send(const ServerCommand& cmd) {
    std::shared_lock lk(session_mu); if (auto s = session.lock()) s->try_send(cmd);
    else spdlog::warn("sending to dangling user {}", id);
}
void User::dangle() {
    spdlog::warn("user {} dangling", id);
    std::shared_ptr<Room> rm;
    { std::shared_lock lk(room_mu); rm = room; }
    if (rm) {
        std::shared_lock lk(rm->state_mu);
        if (rm->state.type == InternalRoomState::Type::Playing) {
            spdlog::warn("user {}: lost in playing, abort", id); lk.unlock();
            { std::unique_lock ul(server->users_mu); server->users.erase(id); }
            if (rm->on_user_leave(*this)) { std::unique_lock rl(server->rooms_mu); server->rooms.erase(rm->id.to_string()); }
            return;
        }
    }
    auto mark = std::make_shared<int>(0);
    { std::lock_guard lk(dangle_mu); dangle_mark = mark; }
    auto timer = std::make_shared<asio::steady_timer>(ioc, std::chrono::seconds(10));
    { std::lock_guard lk(dangle_mu); dangle_timer = timer; }
    auto self = shared_from_this();
    timer->async_wait([self, mark, timer](const error_code& ec) {
        if (ec) return;
        if (mark.use_count() <= 1) return;
        std::shared_ptr<Room> rm;
        { std::shared_lock lk(self->room_mu); rm = self->room; }
        if (rm) {
            { std::unique_lock ul(self->server->users_mu); self->server->users.erase(self->id); }
            if (rm->on_user_leave(*self)) { std::unique_lock rl(self->server->rooms_mu); self->server->rooms.erase(rm->id.to_string()); }
        }
    });
}

// ── Session ───────────────────────────────────────────────────────────
Session::Session(Uuid id, std::shared_ptr<ServerState> srv, asio::io_context& ioc)
    : id(id), server_(std::move(srv)), ioc_(ioc), last_recv_(std::chrono::steady_clock::now()) {}

std::shared_ptr<Session> Session::create(Uuid id, tcp::socket sock, std::shared_ptr<ServerState> srv, asio::io_context& ioc) {
    auto s = std::shared_ptr<Session>(new Session(id, srv, ioc));
    s->stream_ = std::make_shared<TcpBinaryStream>(std::move(sock), ioc);
    auto ws = std::weak_ptr<Session>(s);
    s->stream_->start_server_side(
        [ws](ClientCommand cmd) { if (auto s = ws.lock()) s->on_recv(std::move(cmd)); },
        [ws](const std::string& e) { if (auto s = ws.lock()) s->on_error(e); });
    s->user = std::make_shared<User>(0, "unauthenticated", Lang::EnUS, srv, ioc);
    s->start_heartbeat();
    return s;
}
void Session::try_send(const ServerCommand& cmd) { if (stream_) stream_->send(cmd); }
uint8_t Session::version() const { return stream_ ? stream_->version() : 0; }

void Session::start_heartbeat() {
    hb_timer_ = std::make_shared<asio::steady_timer>(ioc_);
    auto ws = std::weak_ptr<Session>(shared_from_this()); auto srv = server_; auto sid = id;
    auto check = [ws, srv, sid](auto& self, const error_code& ec) {
        if (ec) return; auto s = ws.lock(); if (!s) return;
        auto now = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point last;
        { std::lock_guard lk(s->last_recv_mu_); last = s->last_recv_; }
        if (now - last > HEARTBEAT_DISCONNECT_TIMEOUT) { spdlog::warn("heartbeat timeout {}", sid.to_string()); srv->handle_lost_connection(sid); return; }
        s->hb_timer_->expires_after(HEARTBEAT_DISCONNECT_TIMEOUT);
        s->hb_timer_->async_wait([ws, srv, sid, &self](const error_code& ec) { self(self, ec); });
    };
    hb_timer_->expires_after(HEARTBEAT_DISCONNECT_TIMEOUT);
    hb_timer_->async_wait([check](const error_code& ec) { check(check, ec); });
}

void Session::on_recv(ClientCommand cmd) {
    if (panicked_.load()) return;
    { std::lock_guard lk(last_recv_mu_); last_recv_ = std::chrono::steady_clock::now(); }
    if (cmd.type == ClientCommandType::Ping) { try_send(ServerCommand::make_pong()); return; }
    if (waiting_auth_.load()) { handle_auth(cmd); return; }
    LangContext::set(user->lang);
    auto resp = process(cmd);
    if (resp) try_send(*resp);
}
void Session::on_error(const std::string& e) {
    spdlog::warn("session {} error: {}", id.to_string(), e);
    server_->handle_lost_connection(id);
}

// ── send_room_event helper ────────────────────────────────────────────
static void send_re(std::shared_ptr<ServerState> srv, RoomEvent ev) {
    if (auto rm = srv->get_room_monitor()) rm->try_send(ServerCommand::make_room_event(ev));
}

// ── Send welcome messages and available rooms ─────────────────────────
static void send_welcome(std::shared_ptr<User> u, std::shared_ptr<ServerState> srv) {
    // Welcome messages
    { Message m; m.type = MessageType::Chat; m.user = 0;
      m.content = "欢迎使用HSNPhira多人游戏服务器！";
      u->try_send(ServerCommand::make_message(m)); }
    { Message m; m.type = MessageType::Chat; m.user = 0;
      m.content = "欢迎加入1049578201交流群获取更多咨讯！";
      u->try_send(ServerCommand::make_message(m)); }

    // Show available rooms (unlocked, in SelectChart state)
    std::vector<std::string> available;
    { std::shared_lock lk(srv->rooms_mu);
      for (auto& [name, room] : srv->rooms) {
          if (room->is_locked()) continue;
          std::shared_lock slk(room->state_mu);
          if (room->state.type == InternalRoomState::Type::SelectChart)
              available.push_back(name);
      }
    }
    if (!available.empty()) {
        std::string list = "当前可加入的房间: ";
        for (size_t i = 0; i < available.size(); i++) {
            if (i > 0) list += ", ";
            list += available[i];
        }
        Message m; m.type = MessageType::Chat; m.user = 0;
        m.content = list;
        u->try_send(ServerCommand::make_message(m));
    } else {
        Message m; m.type = MessageType::Chat; m.user = 0;
        m.content = "当前没有可加入的房间，快创建一个吧！";
        u->try_send(ServerCommand::make_message(m));
    }
}

// ── handle_auth ───────────────────────────────────────────────────────
void Session::handle_auth(const ClientCommand& cmd) {
    if (cmd.type == ClientCommandType::Authenticate || cmd.type == ClientCommandType::GameMonitorAuthenticate) {
        auto self = shared_from_this();
        auto srv  = server_;
        auto sid  = id;
        auto token = cmd.token;
        auto cmd_type = cmd.type;

        std::thread([self, srv, sid, token, cmd_type]() {
            try {
                auto r = authenticate_http(token);
                asio::post(self->ioc_, [self, srv, sid, r, cmd_type]() {
                    if (self->panicked_.load()) return;

                    // ── Ban check ──
                    auto r2 = r;
                    if (srv->is_banned(r2.id)) {
                        spdlog::info("banned user {} tried to connect", r2.id);
                        self->try_send(ServerCommand::make_auth_err("你已被管理员封禁，请加入交流群1049578201联系群主查看详情。"));
                        self->panicked_.store(true);
                        srv->handle_lost_connection(sid);
                        return;
                    }

                    SessionCategory cat = SessionCategory::Normal;
                    if (cmd_type == ClientCommandType::GameMonitorAuthenticate) {
                        cat = SessionCategory::GameMonitor; r2.id = -r2.id; r2.name += " (monitor)";
                    }
                    self->category = cat;
                    std::shared_ptr<User> up;
                    { std::unique_lock lk(srv->users_mu);
                      auto it = srv->users.find(r2.id);
                      if (it != srv->users.end()) { spdlog::info("reconnect user {}", r2.id); up = it->second; }
                      else { up = std::make_shared<User>(r2.id, r2.name, parse_language(r2.language), srv, self->ioc_); srv->users[r2.id] = up; }
                    }
                    self->user = up; up->set_session(self->weak_from_this());
                    if (cat == SessionCategory::GameMonitor) srv->set_game_monitor(r2.id, self->weak_from_this());
                    std::optional<ClientRoomState> rs;
                    { std::shared_lock lk(up->room_mu); if (up->room) rs = up->room->client_state(*up); }
                    self->try_send(ServerCommand::make_auth_ok(up->to_info(), rs));
                    if (auto rm = srv->get_room_monitor()) rm->try_send(ServerCommand::make_user_visit(up->id));
                    self->waiting_auth_.store(false);

                    // ── Welcome messages + available rooms ──
                    if (cat == SessionCategory::Normal) {
                        send_welcome(up, srv);
                    }
                });
            } catch (const std::exception& e) {
                std::string err = e.what();
                asio::post(self->ioc_, [self, srv, sid, err]() {
                    spdlog::warn("auth fail: {}", err); self->try_send(ServerCommand::make_auth_err(err));
                    self->panicked_.store(true); srv->handle_lost_connection(sid);
                });
            }
        }).detach();

    } else if (cmd.type == ClientCommandType::ConsoleAuthenticate) {
        auto self = shared_from_this();
        auto srv  = server_;
        auto sid  = id;
        auto token = cmd.token;

        std::thread([self, srv, sid, token]() {
            try {
                auto r = authenticate_http(token);
                asio::post(self->ioc_, [self, srv, r]() {
                    if (self->panicked_.load()) return;
                    self->category = SessionCategory::Console;
                    auto up = std::make_shared<User>(r.id, r.name, parse_language(r.language), srv, self->ioc_);
                    self->user = up; up->set_session(self->weak_from_this());
                    self->try_send(ServerCommand::make_auth_ok(up->to_info(), std::nullopt));
                    self->waiting_auth_.store(false);
                });
            } catch (const std::exception& e) {
                std::string err = e.what();
                asio::post(self->ioc_, [self, srv, sid, err]() {
                    spdlog::warn("console auth fail: {}", err); self->try_send(ServerCommand::make_auth_err(err));
                    self->panicked_.store(true); srv->handle_lost_connection(sid);
                });
            }
        }).detach();

    } else if (cmd.type == ClientCommandType::RoomMonitorAuthenticate) {
        if (server_->get_room_monitor()) { try_send(ServerCommand::make_auth_err("more than one room monitor")); panicked_.store(true); server_->handle_lost_connection(id); }
        else if (server_->room_monitor_key == cmd.key) {
            spdlog::info("new room monitor connected"); category = SessionCategory::RoomMonitor;
            auto up = std::make_shared<User>(-1, "$server_room_monitor", Lang::EnUS, server_, ioc_);
            user = up; up->set_session(weak_from_this());
            try_send(ServerCommand::make_auth_ok(up->to_info(), std::nullopt));
            { std::unique_lock lk(server_->rm_mu); server_->room_monitor = weak_from_this(); }
            waiting_auth_.store(false);
        } else { try_send(ServerCommand::make_auth_err("secret key mismatch")); panicked_.store(true); server_->handle_lost_connection(id); }
    } else { spdlog::warn("packet before auth, ignoring"); }
}

// ── SSE emit helper for room events ──────────────────────────────────
static void emit_room_sse(std::shared_ptr<ServerState> srv, const std::string& event_type, const nlohmann::json& data) {
    srv->emit_sse(event_type, data.dump());
}

// ── process (authenticated commands) ──────────────────────────────────
std::optional<ServerCommand> Session::process(const ClientCommand& cmd) {
    auto& u = user; auto srv = server_;
    auto get_room = [&]() -> std::shared_ptr<Room> { std::shared_lock lk(u->room_mu); return u->room; };

    switch (cmd.type) {
    case ClientCommandType::Ping: return std::nullopt;
    case ClientCommandType::Authenticate: case ClientCommandType::ConsoleAuthenticate:
    case ClientCommandType::RoomMonitorAuthenticate: case ClientCommandType::GameMonitorAuthenticate:
        return ServerCommand::make_auth_err("repeated authenticate");

    case ClientCommandType::Chat: {
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::Chat, "no room");
        rm->send_as(*u, cmd.message); return ServerCommand::make_ok(ServerCommandType::Chat);
    }
    case ClientCommandType::Touches: {
        auto rm = get_room(); if (!rm) return std::nullopt;
        if (rm->is_live()) {
            if (!cmd.frames.empty()) { uint32_t b; float t = cmd.frames.back().time; std::memcpy(&b, &t, 4); u->game_time.store(b, std::memory_order_seq_cst); }
            rm->broadcast_monitors(ServerCommand::make_touches(u->id, cmd.frames));
        }
        return std::nullopt;
    }
    case ClientCommandType::Judges: {
        auto rm = get_room(); if (!rm) return std::nullopt;
        if (rm->is_live()) rm->broadcast_monitors(ServerCommand::make_judges(u->id, cmd.judges));
        return std::nullopt;
    }
    case ClientCommandType::CreateRoom: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::CreateRoom, "invalid session");
        { std::shared_lock lk(u->room_mu); if (u->room) return ServerCommand::make_err(ServerCommandType::CreateRoom, "already in room"); }
        auto rm = std::make_shared<Room>(cmd.room_id, std::weak_ptr<User>(u));
        { std::unique_lock lk(srv->rooms_mu);
          if (srv->rooms.count(cmd.room_id.to_string())) return ServerCommand::make_err(ServerCommandType::CreateRoom, TL("create-id-occupied"));
          srv->rooms[cmd.room_id.to_string()] = rm;
        }
        { Message m; m.type = MessageType::CreateRoom; m.user = u->id; rm->send_msg(m); }
        { RoomEvent ev; ev.type = RoomEventType::CreateRoom; ev.room = cmd.room_id; ev.data = rm->into_data(); send_re(srv, ev); }
        { std::unique_lock lk(u->room_mu); u->room = rm; }
        spdlog::info("user {} create room {}", u->id, cmd.room_id.to_string());

        // SSE: create_room event
        { nlohmann::json data;
          data["host"] = u->id;
          data["users"] = nlohmann::json::array({u->id});
          data["lock"] = false; data["cycle"] = false;
          data["chart"] = nullptr; data["state"] = "SELECTING_CHART";
          data["playing_users"] = nlohmann::json::array();
          data["rounds"] = nlohmann::json::array();
          emit_room_sse(srv, "create_room", {{"room", cmd.room_id.to_string()}, {"data", data}});
        }

        return ServerCommand::make_ok(ServerCommandType::CreateRoom);
    }
    case ClientCommandType::JoinRoom: {
        if (category != SessionCategory::Normal && category != SessionCategory::GameMonitor) return ServerCommand::make_err(ServerCommandType::JoinRoom, "invalid session");
        if (!cmd.monitor && category == SessionCategory::GameMonitor) return ServerCommand::make_err(ServerCommandType::JoinRoom, "monitor=false in game monitor");
        { std::shared_lock lk(u->room_mu); if (u->room) return ServerCommand::make_err(ServerCommandType::JoinRoom, "already in room"); }
        std::shared_ptr<Room> rm;
        { std::shared_lock lk(srv->rooms_mu); auto it = srv->rooms.find(cmd.room_id.to_string()); if (it == srv->rooms.end()) return ServerCommand::make_err(ServerCommandType::JoinRoom, "room not found"); rm = it->second; }
        if (rm->is_locked()) return ServerCommand::make_err(ServerCommandType::JoinRoom, TL("join-room-locked"));
        { std::shared_lock lk(rm->state_mu); if (rm->state.type != InternalRoomState::Type::SelectChart) return ServerCommand::make_err(ServerCommandType::JoinRoom, TL("join-game-ongoing")); }
        if (cmd.monitor && category != SessionCategory::GameMonitor) return ServerCommand::make_err(ServerCommandType::JoinRoom, TL("join-cant-monitor"));
        if (!rm->add_user(std::weak_ptr<User>(u), cmd.monitor)) return ServerCommand::make_err(ServerCommandType::JoinRoom, TL("join-room-full"));
        u->monitor.store(cmd.monitor, std::memory_order_seq_cst);
        if (cmd.monitor && !rm->is_live()) { rm->set_live(true); spdlog::info("room {} goes live", cmd.room_id.to_string()); }
        rm->broadcast(ServerCommand::make_on_join(u->to_info()));
        { Message m; m.type = MessageType::JoinRoom; m.user = u->id; m.name = u->name; rm->send_msg(m); }
        if (!cmd.monitor) { RoomEvent ev; ev.type = RoomEventType::JoinRoom; ev.room = cmd.room_id; ev.user_id = u->id; send_re(srv, ev); }
        { std::unique_lock lk(u->room_mu); u->room = rm; }
        JoinRoomResponse resp; resp.state = rm->client_room_state();
        for (auto& p : rm->get_users()) resp.users.push_back(p->to_info());
        for (auto& p : rm->get_monitors()) resp.users.push_back(p->to_info());
        resp.live = rm->is_live();

        // SSE: join_room event
        if (!cmd.monitor) emit_room_sse(srv, "join_room", {{"room", cmd.room_id.to_string()}, {"user", u->id}});

        return ServerCommand::make_join_ok(resp);
    }
    case ClientCommandType::LeaveRoom: {
        if (category != SessionCategory::Normal && category != SessionCategory::GameMonitor) return ServerCommand::make_err(ServerCommandType::LeaveRoom, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::LeaveRoom, "no room");
        spdlog::info("user {} leave room {}", u->id, rm->id.to_string());
        auto room_name = rm->id.to_string();
        if (rm->on_user_leave(*u)) { std::unique_lock lk(srv->rooms_mu); srv->rooms.erase(room_name); }
        { RoomEvent ev; ev.type = RoomEventType::LeaveRoom; ev.room = rm->id; ev.user_id = u->id; send_re(srv, ev); }

        // SSE: leave_room event
        emit_room_sse(srv, "leave_room", {{"room", room_name}, {"user", u->id}});

        return ServerCommand::make_ok(ServerCommandType::LeaveRoom);
    }
    case ClientCommandType::LockRoom: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::LockRoom, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::LockRoom, "no room");
        try { rm->check_host_throw(*u); } catch (...) { return ServerCommand::make_err(ServerCommandType::LockRoom, "only host"); }
        rm->set_locked(cmd.lock_val);
        { Message m; m.type = MessageType::LockRoom; m.lock_val = cmd.lock_val; rm->send_msg(m); }
        { PartialRoomData pd; pd.lock = cmd.lock_val; RoomEvent ev; ev.type = RoomEventType::UpdateRoom; ev.room = rm->id; ev.partial = pd; send_re(srv, ev); }
        // SSE
        emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"lock", cmd.lock_val}}}});
        return ServerCommand::make_ok(ServerCommandType::LockRoom);
    }
    case ClientCommandType::CycleRoom: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::CycleRoom, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::CycleRoom, "no room");
        try { rm->check_host_throw(*u); } catch (...) { return ServerCommand::make_err(ServerCommandType::CycleRoom, "only host"); }
        rm->set_cycle(cmd.cycle_val);
        { Message m; m.type = MessageType::CycleRoom; m.cycle_val = cmd.cycle_val; rm->send_msg(m); }
        { PartialRoomData pd; pd.cycle = cmd.cycle_val; RoomEvent ev; ev.type = RoomEventType::UpdateRoom; ev.room = rm->id; ev.partial = pd; send_re(srv, ev); }
        emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"cycle", cmd.cycle_val}}}});
        return ServerCommand::make_ok(ServerCommandType::CycleRoom);
    }
    case ClientCommandType::SelectChart: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::SelectChart, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::SelectChart, "no room");
        { std::shared_lock lk(rm->state_mu); if (rm->state.type != InternalRoomState::Type::SelectChart) return ServerCommand::make_err(ServerCommandType::SelectChart, "invalid state"); }
        try { rm->check_host_throw(*u); } catch (...) { return ServerCommand::make_err(ServerCommandType::SelectChart, "only host"); }
        try {
            auto body = http_get(PHIRA_HOST + "/chart/" + std::to_string(cmd.chart_id));
            auto j = nlohmann::json::parse(body); ChartInfo ci; ci.id = j.at("id").get<int32_t>(); ci.name = j.at("name").get<std::string>();
            { Message m; m.type = MessageType::SelectChart; m.user = u->id; m.name = ci.name; m.chart_id = ci.id; rm->send_msg(m); }
            { std::unique_lock lk(rm->chart_mu); rm->chart = ci; }
            rm->on_state_change();
            { PartialRoomData pd; pd.chart = cmd.chart_id; RoomEvent ev; ev.type = RoomEventType::UpdateRoom; ev.room = rm->id; ev.partial = pd; send_re(srv, ev); }
            emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"chart", cmd.chart_id}}}});
            return ServerCommand::make_ok(ServerCommandType::SelectChart);
        } catch (const std::exception& e) { return ServerCommand::make_err(ServerCommandType::SelectChart, e.what()); }
    }
    case ClientCommandType::RequestStart: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::RequestStart, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::RequestStart, "no room");
        { std::shared_lock lk(rm->state_mu); if (rm->state.type != InternalRoomState::Type::SelectChart) return ServerCommand::make_err(ServerCommandType::RequestStart, "invalid state"); }
        try { rm->check_host_throw(*u); } catch (...) { return ServerCommand::make_err(ServerCommandType::RequestStart, "only host"); }
        { std::shared_lock lk(rm->chart_mu); if (!rm->chart) return ServerCommand::make_err(ServerCommandType::RequestStart, TL("start-no-chart-selected")); }
        rm->reset_game_time();
        { Message m; m.type = MessageType::GameStart; m.user = u->id; rm->send_msg(m); }
        { std::unique_lock lk(rm->state_mu); rm->state.type = InternalRoomState::Type::WaitForReady; rm->state.started.clear(); rm->state.started.insert(u->id); }
        rm->on_state_change(); rm->check_all_ready();
        { std::shared_lock lk(rm->state_mu); PartialRoomData pd; pd.state = rm->state.to_stripped(); RoomEvent ev; ev.type = RoomEventType::UpdateRoom; ev.room = rm->id; ev.partial = pd; send_re(srv, ev); }
        emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"state", "WAITING_FOR_READY"}}}});
        emit_room_sse(srv, "start_round", {{"room", rm->id.to_string()}});
        return ServerCommand::make_ok(ServerCommandType::RequestStart);
    }
    case ClientCommandType::Ready: {
        if (category != SessionCategory::Normal && category != SessionCategory::GameMonitor) return ServerCommand::make_err(ServerCommandType::Ready, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::Ready, "no room");
        { std::unique_lock lk(rm->state_mu);
          if (rm->state.type == InternalRoomState::Type::WaitForReady) {
              if (!rm->state.started.insert(u->id).second) return ServerCommand::make_err(ServerCommandType::Ready, "already ready");
          }
        }
        { Message m; m.type = MessageType::Ready; m.user = u->id; rm->send_msg(m); }
        rm->check_all_ready();
        { std::shared_lock lk(rm->state_mu);
          if (rm->state.type == InternalRoomState::Type::Playing) {
              PartialRoomData pd; pd.state = StrippedRoomState::Playing; RoomEvent ev; ev.type = RoomEventType::UpdateRoom; ev.room = rm->id; ev.partial = pd; send_re(srv, ev);
              emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"state", "PLAYING"}}}});
          }
        }
        return ServerCommand::make_ok(ServerCommandType::Ready);
    }
    case ClientCommandType::CancelReady: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::CancelReady, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::CancelReady, "no room");
        { std::unique_lock lk(rm->state_mu);
          if (rm->state.type == InternalRoomState::Type::WaitForReady) {
              if (!rm->state.started.erase(u->id)) return ServerCommand::make_err(ServerCommandType::CancelReady, "not ready");
              bool is_host = false; try { rm->check_host_throw(*u); is_host = true; } catch (...) {}
              if (is_host) { Message m; m.type = MessageType::CancelGame; m.user = u->id; rm->send_msg(m);
                  rm->state.type = InternalRoomState::Type::SelectChart; rm->state.started.clear();
                  lk.unlock(); rm->on_state_change();
                  emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"state", "SELECTING_CHART"}}}});
              } else { Message m; m.type = MessageType::CancelReady; m.user = u->id; rm->send_msg(m); }
          }
        }
        return ServerCommand::make_ok(ServerCommandType::CancelReady);
    }
    case ClientCommandType::Played: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::Played, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::Played, "no room");
        try {
            auto body = http_get(PHIRA_HOST + "/record/" + std::to_string(cmd.chart_id));
            Record rec = Record::from_json(body);
            if (rec.player != u->id) return ServerCommand::make_err(ServerCommandType::Played, "invalid record");
            { Message m; m.type = MessageType::Played; m.user = u->id; m.score_val = rec.score; m.accuracy = rec.accuracy; m.full_combo = rec.full_combo; rm->send_msg(m); }
            { std::unique_lock lk(rm->state_mu);
              if (rm->state.type == InternalRoomState::Type::Playing) {
                  if (rm->state.aborted.count(u->id)) return ServerCommand::make_err(ServerCommandType::Played, "aborted");
                  if (rm->state.results.count(u->id)) return ServerCommand::make_err(ServerCommandType::Played, "already uploaded");
                  rm->state.results[u->id] = rec;
              }
            }

            // SSE: player_score
            emit_room_sse(srv, "player_score", {{"room", rm->id.to_string()}, {"record", {
                {"id", rec.id}, {"player", rec.player}, {"score", rec.score},
                {"perfect", rec.perfect}, {"good", rec.good}, {"bad", rec.bad},
                {"miss", rec.miss}, {"max_combo", rec.max_combo},
                {"accuracy", rec.accuracy}, {"full_combo", rec.full_combo},
                {"std", rec.std_val}, {"std_score", rec.std_score}
            }}});

            rm->check_all_ready();
            { std::shared_lock lk(rm->state_mu);
              if (rm->state.type == InternalRoomState::Type::SelectChart) {
                  { std::shared_lock rl(rm->rounds_mu); if (!rm->rounds.empty()) { RoomEvent ev; ev.type = RoomEventType::NewRound; ev.room = rm->id; ev.round = rm->rounds.back(); send_re(srv, ev); } }
                  PartialRoomData pd; pd.state = StrippedRoomState::SelectingChart; RoomEvent ev; ev.type = RoomEventType::UpdateRoom; ev.room = rm->id; ev.partial = pd; send_re(srv, ev);
                  emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"state", "SELECTING_CHART"}}}});
              }
            }
            return ServerCommand::make_ok(ServerCommandType::Played);
        } catch (const std::exception& e) { return ServerCommand::make_err(ServerCommandType::Played, e.what()); }
    }
    case ClientCommandType::Abort: {
        if (category != SessionCategory::Normal) return ServerCommand::make_err(ServerCommandType::Abort, "invalid session");
        auto rm = get_room(); if (!rm) return ServerCommand::make_err(ServerCommandType::Abort, "no room");
        { std::unique_lock lk(rm->state_mu);
          if (rm->state.type == InternalRoomState::Type::Playing) {
              if (rm->state.results.count(u->id)) return ServerCommand::make_err(ServerCommandType::Abort, "already uploaded");
              if (!rm->state.aborted.insert(u->id).second) return ServerCommand::make_err(ServerCommandType::Abort, "aborted");
          }
        }
        { Message m; m.type = MessageType::Abort; m.user = u->id; rm->send_msg(m); }
        rm->check_all_ready();
        { std::shared_lock lk(rm->state_mu);
          if (rm->state.type == InternalRoomState::Type::SelectChart) {
              PartialRoomData pd; pd.state = StrippedRoomState::SelectingChart; RoomEvent ev; ev.type = RoomEventType::UpdateRoom; ev.room = rm->id; ev.partial = pd; send_re(srv, ev);
              emit_room_sse(srv, "update_room", {{"room", rm->id.to_string()}, {"data", {{"state", "SELECTING_CHART"}}}});
          }
        }
        return ServerCommand::make_ok(ServerCommandType::Abort);
    }
    case ClientCommandType::QueryRoomInfo: {
        if (category != SessionCategory::RoomMonitor) return ServerCommand::make_err(ServerCommandType::RoomResponse, "invalid session");
        std::map<std::string, RoomData> info; std::map<int32_t, std::string> urm;
        { std::shared_lock lk(srv->rooms_mu);
          for (auto& [rid, room] : srv->rooms) {
              for (auto& up : room->get_users()) urm[up->id] = rid;
              info[rid] = room->into_data();
          }
        }
        return ServerCommand::make_room_response(info, urm);
    }
    default: return std::nullopt;
    }
}
