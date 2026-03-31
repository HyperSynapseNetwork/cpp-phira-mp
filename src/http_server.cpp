#include "http_server.hpp"
#include "server.hpp"
#include <spdlog/spdlog.h>
#include <thread>

// ═══════════════════════════════════════════════════════════════════════
// SSE Connection — blocking design
//
// Each SSE client gets its own thread.  The thread blocks on a
// condition-variable, wakes when an event is enqueued, and does a
// synchronous write.  The thread only exits when the client
// disconnects (write returns an error) or close() is called.
// ═══════════════════════════════════════════════════════════════════════
SseConnection::SseConnection(tcp::socket sock) : socket_(std::move(sock)) {}

bool SseConnection::is_open() const { std::lock_guard<std::mutex> lk(mu_); return !closed_; }

void SseConnection::close() {
    { std::lock_guard<std::mutex> lk(mu_); closed_ = true; }
    cv_.notify_all();
    boost::system::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

void SseConnection::send_event(const std::string& event_type, const std::string& data) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return;
        std::string msg = "event: " + event_type + "\ndata: " + data + "\n\n";
        queue_.push(std::move(msg));
    }
    cv_.notify_one();
}

void SseConnection::run(const std::string& initial_data) {
    // 1) Send SSE response headers + initial events synchronously
    std::string header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n";
    header += initial_data;

    boost::system::error_code ec;
    asio::write(socket_, asio::buffer(header), ec);
    if (ec) { std::lock_guard<std::mutex> lk(mu_); closed_ = true; return; }

    // 2) Event loop: block until events arrive, write them out
    while (true) {
        std::string payload;
        {
            std::unique_lock<std::mutex> lk(mu_);
            // Wait up to 15s for an event; if none, send a keepalive comment
            cv_.wait_for(lk, std::chrono::seconds(15), [this]{ return closed_ || !queue_.empty(); });
            if (closed_) return;
            if (queue_.empty()) {
                // keepalive
                payload = ": keepalive\n\n";
            } else {
                // drain all pending events into one payload
                while (!queue_.empty()) {
                    payload += queue_.front();
                    queue_.pop();
                }
            }
        }
        asio::write(socket_, asio::buffer(payload), ec);
        if (ec) { std::lock_guard<std::mutex> lk(mu_); closed_ = true; return; }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// SSE Broadcaster — holds shared_ptr to keep connections alive
// ═══════════════════════════════════════════════════════════════════════
void SseBroadcaster::add(std::shared_ptr<SseConnection> conn) {
    std::lock_guard<std::mutex> lk(mu_);
    connections_.push_back(std::move(conn));
}

void SseBroadcaster::broadcast(const std::string& event_type, const std::string& data) {
    std::lock_guard<std::mutex> lk(mu_);
    // Send to all open connections, remove dead ones
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
            [](auto& c){ return !c->is_open(); }),
        connections_.end());
    for (auto& c : connections_) {
        c->send_event(event_type, data);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP Server
// ═══════════════════════════════════════════════════════════════════════
HttpServer::HttpServer(asio::io_context& ioc, uint16_t port,
                       std::shared_ptr<ServerState> state,
                       const std::string& admin_password)
    : ioc_(ioc),
      acceptor_(ioc, tcp::endpoint(asio::ip::address_v6::any(), port)),
      state_(state), admin_password_(admin_password)
{
    acceptor_.set_option(asio::socket_base::reuse_address(true));
}

void HttpServer::start() {
    spdlog::info("HTTP server listening on port {}", acceptor_.local_endpoint().port());
    do_accept();
}

void HttpServer::do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket sock) {
        if (!ec) handle_request(std::move(sock));
        do_accept();
    });
}

void HttpServer::handle_request(tcp::socket sock) {
    auto state = state_;
    auto admin_pw = admin_password_;
    auto* broadcaster = &broadcaster_;

    std::thread([state, admin_pw, broadcaster](tcp::socket sock) {
        try {
            beast::flat_buffer buf;
            http::request<http::string_body> req;
            http::read(sock, buf, req);

            RequestHandler handler(state, admin_pw, *broadcaster);

            // ── SSE path: the thread stays alive for the duration of the stream ──
            if (handler.is_sse_request(req)) {
                auto initial = handler.get_sse_initial_data();
                auto conn = std::make_shared<SseConnection>(std::move(sock));
                broadcaster->add(conn);
                spdlog::info("SSE client connected");
                conn->run(initial);  // blocks until client disconnects
                spdlog::info("SSE client disconnected");
                return;
            }

            // ── Normal HTTP path ──
            http::response<http::string_body> res;
            res.version(req.version());
            res.set(http::field::server, "phira-mp-cpp");
            res.set(http::field::access_control_allow_origin, "*");
            res.set(http::field::access_control_allow_headers, "Content-Type, Authorization, X-Admin-Password");
            res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");

            if (req.method() == http::verb::options) {
                res.result(http::status::no_content);
                res.prepare_payload();
                http::write(sock, res);
                return;
            }

            handler.handle(req, res);
            res.prepare_payload();
            http::write(sock, res);
        } catch (const std::exception& e) {
            spdlog::debug("HTTP session error: {}", e.what());
        }
    }, std::move(sock)).detach();
}

// ═══════════════════════════════════════════════════════════════════════
// Request Handler
// ═══════════════════════════════════════════════════════════════════════
RequestHandler::RequestHandler(std::shared_ptr<ServerState> state,
                               const std::string& admin_password,
                               SseBroadcaster& broadcaster)
    : state_(state), admin_password_(admin_password), broadcaster_(broadcaster) {}

bool RequestHandler::is_sse_request(const http::request<http::string_body>& req) const {
    auto target = std::string(req.target());
    auto qpos = target.find('?');
    if (qpos != std::string::npos) target = target.substr(0, qpos);
    return target == "/api/rooms/listen" && req.method() == http::verb::get;
}

std::string RequestHandler::get_sse_initial_data() {
    std::string result;
    std::shared_lock lk(state_->rooms_mu);
    for (auto& [name, room] : state_->rooms) {
        auto j = room_data_to_json(name, room);
        result += "event: create_room\ndata: " + j.dump() + "\n\n";
    }
    return result;
}

bool RequestHandler::handle(http::request<http::string_body>& req,
                            http::response<http::string_body>& res) {
    auto target = std::string(req.target());
    auto qpos = target.find('?');
    if (qpos != std::string::npos) target = target.substr(0, qpos);

    res.set(http::field::content_type, "application/json");

    if (req.method() == http::verb::get) {
        if (target == "/api/rooms/info") { handle_rooms_info(res); return true; }
        if (target.rfind("/api/rooms/info/", 0) == 0) { handle_room_by_name(target.substr(16), res); return true; }
        if (target.rfind("/api/rooms/user/", 0) == 0) {
            try { handle_room_by_user(std::stoi(target.substr(16)), res); }
            catch (...) { res.result(http::status::bad_request); res.body() = R"({"error":"invalid user id"})"; }
            return true;
        }
        if (target == "/admin" || target == "/admin/") { handle_admin_page(res); return true; }
        if (target == "/api/admin/banned") {
            if (!check_admin_auth(req)) { res.result(http::status::unauthorized); res.body() = R"({"error":"unauthorized"})"; return true; }
            handle_admin_banned_list(res); return true;
        }
    }

    if (req.method() == http::verb::post) {
        if (!check_admin_auth(req)) { res.result(http::status::unauthorized); res.body() = R"({"error":"unauthorized"})"; return true; }
        auto body = req.body();
        if (target == "/api/admin/create-room") { handle_admin_create_room(body, res); return true; }
        if (target == "/api/admin/delete-room") { handle_admin_delete_room(body, res); return true; }
        if (target == "/api/admin/kick-user") { handle_admin_kick_user(body, res); return true; }
        if (target == "/api/admin/ban-user") { handle_admin_ban_user(body, res); return true; }
        if (target == "/api/admin/unban-user") { handle_admin_unban_user(body, res); return true; }
    }

    res.result(http::status::not_found);
    res.body() = R"({"error":"not found"})";
    return true;
}

// ── API helpers ───────────────────────────────────────────────────────
nlohmann::json RequestHandler::room_data_to_json(const std::string& name, std::shared_ptr<Room> room) {
    nlohmann::json data;
    { std::shared_lock lk(room->host_mu); auto h = room->host.lock(); data["host"] = h ? h->id : -1; }
    nlohmann::json users_arr = nlohmann::json::array();
    for (auto& u : room->get_users()) users_arr.push_back(u->id);
    data["users"] = users_arr;
    data["lock"] = room->is_locked();
    data["cycle"] = room->is_cycle();
    { std::shared_lock lk(room->chart_mu); data["chart"] = room->chart ? nlohmann::json(room->chart->id) : nlohmann::json(nullptr); }
    std::string state_str;
    { std::shared_lock lk(room->state_mu);
      switch (room->state.type) {
          case InternalRoomState::Type::SelectChart: state_str = "SELECTING_CHART"; break;
          case InternalRoomState::Type::WaitForReady: state_str = "WAITING_FOR_READY"; break;
          case InternalRoomState::Type::Playing: state_str = "PLAYING"; break;
      }
    }
    data["state"] = state_str;
    nlohmann::json playing_arr = nlohmann::json::array();
    { std::shared_lock lk(room->state_mu);
      if (room->state.type == InternalRoomState::Type::Playing) {
          for (auto& u : room->get_users())
              if (!room->state.results.count(u->id) && !room->state.aborted.count(u->id))
                  playing_arr.push_back(u->id);
      }
    }
    data["playing_users"] = playing_arr;
    nlohmann::json rounds_arr = nlohmann::json::array();
    { std::shared_lock lk(room->rounds_mu);
      for (auto& rd : room->rounds) {
          nlohmann::json rj;
          rj["chart"] = rd.chart;
          nlohmann::json recs = nlohmann::json::array();
          for (auto& rec : rd.records) {
              recs.push_back({{"id", rec.id}, {"player", rec.player}, {"score", rec.score},
                  {"perfect", rec.perfect}, {"good", rec.good}, {"bad", rec.bad},
                  {"miss", rec.miss}, {"max_combo", rec.max_combo},
                  {"accuracy", rec.accuracy}, {"full_combo", rec.full_combo},
                  {"std", rec.std_val}, {"std_score", rec.std_score}});
          }
          rj["records"] = recs;
          rounds_arr.push_back(rj);
      }
    }
    data["rounds"] = rounds_arr;
    return {{"name", name}, {"data", data}};
}

void RequestHandler::handle_rooms_info(http::response<http::string_body>& res) {
    nlohmann::json arr = nlohmann::json::array();
    std::shared_lock lk(state_->rooms_mu);
    for (auto& [name, room] : state_->rooms) arr.push_back(room_data_to_json(name, room));
    res.result(http::status::ok); res.body() = arr.dump();
}

void RequestHandler::handle_room_by_name(const std::string& name, http::response<http::string_body>& res) {
    std::shared_lock lk(state_->rooms_mu);
    auto it = state_->rooms.find(name);
    if (it == state_->rooms.end()) { res.result(http::status::not_found); res.body() = R"({"error":"room not found"})"; return; }
    res.result(http::status::ok); res.body() = room_data_to_json(name, it->second).dump();
}

void RequestHandler::handle_room_by_user(int32_t user_id, http::response<http::string_body>& res) {
    std::shared_lock lk(state_->users_mu);
    auto uit = state_->users.find(user_id);
    if (uit == state_->users.end()) { res.result(http::status::not_found); res.body() = R"({"error":"user not found"})"; return; }
    auto user = uit->second; lk.unlock();
    std::shared_ptr<Room> rm;
    { std::shared_lock rlk(user->room_mu); rm = user->room; }
    if (!rm) { res.result(http::status::not_found); res.body() = R"({"error":"user not in any room"})"; return; }
    res.result(http::status::ok); res.body() = room_data_to_json(rm->id.to_string(), rm).dump();
}

bool RequestHandler::check_admin_auth(const http::request<http::string_body>& req) {
    auto it = req.find("X-Admin-Password");
    if (it != req.end()) return std::string(it->value()) == admin_password_;
    auto ait = req.find(http::field::authorization);
    if (ait != req.end()) { std::string val(ait->value()); if (val.rfind("Bearer ", 0) == 0) return val.substr(7) == admin_password_; }
    return false;
}

void RequestHandler::handle_admin_create_room(const std::string& body, http::response<http::string_body>& res) {
    try {
        auto j = nlohmann::json::parse(body); std::string name = j.at("name").get<std::string>();
        RoomId rid(name);
        std::unique_lock lk(state_->rooms_mu);
        if (state_->rooms.count(name)) { res.result(http::status::conflict); res.body() = R"({"error":"room already exists"})"; return; }
        auto room = std::make_shared<Room>(rid, std::weak_ptr<User>()); state_->rooms[name] = room; lk.unlock();
        nlohmann::json data; data["host"]=-1; data["users"]=nlohmann::json::array(); data["lock"]=false; data["cycle"]=false;
        data["chart"]=nullptr; data["state"]="SELECTING_CHART"; data["playing_users"]=nlohmann::json::array(); data["rounds"]=nlohmann::json::array();
        broadcaster_.broadcast("create_room", nlohmann::json({{"room",name},{"data",data}}).dump());
        spdlog::info("Admin created room: {}", name);
        res.result(http::status::ok); res.body() = R"({"ok":true})";
    } catch (const std::exception& e) { res.result(http::status::bad_request); res.body() = nlohmann::json({{"error",e.what()}}).dump(); }
}

void RequestHandler::handle_admin_delete_room(const std::string& body, http::response<http::string_body>& res) {
    try {
        auto j = nlohmann::json::parse(body); std::string name = j.at("name").get<std::string>();
        std::shared_ptr<Room> rm;
        { std::unique_lock lk(state_->rooms_mu); auto it = state_->rooms.find(name);
          if (it == state_->rooms.end()) { res.result(http::status::not_found); res.body() = R"({"error":"room not found"})"; return; }
          rm = it->second; state_->rooms.erase(it); }
        for (auto& u : rm->get_users()) { Message m; m.type=MessageType::LeaveRoom; m.user=u->id; m.name=u->name; rm->send_msg(m); { std::unique_lock lk(u->room_mu); u->room.reset(); } }
        for (auto& u : rm->get_monitors()) { std::unique_lock lk(u->room_mu); u->room.reset(); }
        broadcaster_.broadcast("leave_room", nlohmann::json({{"room",name},{"user",-1}}).dump());
        spdlog::info("Admin deleted room: {}", name);
        res.result(http::status::ok); res.body() = R"({"ok":true})";
    } catch (const std::exception& e) { res.result(http::status::bad_request); res.body() = nlohmann::json({{"error",e.what()}}).dump(); }
}

void RequestHandler::handle_admin_kick_user(const std::string& body, http::response<http::string_body>& res) {
    try {
        auto j = nlohmann::json::parse(body); int32_t user_id = j.at("user_id").get<int32_t>();
        std::shared_ptr<User> user;
        { std::shared_lock lk(state_->users_mu); auto it = state_->users.find(user_id);
          if (it == state_->users.end()) { res.result(http::status::not_found); res.body() = R"({"error":"user not found"})"; return; } user = it->second; }
        std::shared_ptr<Room> rm; { std::shared_lock lk(user->room_mu); rm = user->room; }
        if (!rm) { res.result(http::status::bad_request); res.body() = R"({"error":"user not in a room"})"; return; }
        { Message m; m.type=MessageType::Chat; m.user=0; m.content="\xe4\xbd\xa0\xe5\xb7\xb2\xe8\xa2\xab\xe7\xae\xa1\xe7\x90\x86\xe5\x91\x98\xe8\xb8\xa2\xe5\x87\xba\xe6\x88\xbf\xe9\x97\xb4\xe3\x80\x82"; user->try_send(ServerCommand::make_message(m)); }
        if (rm->on_user_leave(*user)) { std::unique_lock lk(state_->rooms_mu); state_->rooms.erase(rm->id.to_string()); }
        broadcaster_.broadcast("leave_room", nlohmann::json({{"room",rm->id.to_string()},{"user",user_id}}).dump());
        spdlog::info("Admin kicked user {} from room {}", user_id, rm->id.to_string());
        res.result(http::status::ok); res.body() = R"({"ok":true})";
    } catch (const std::exception& e) { res.result(http::status::bad_request); res.body() = nlohmann::json({{"error",e.what()}}).dump(); }
}

void RequestHandler::handle_admin_ban_user(const std::string& body, http::response<http::string_body>& res) {
    try {
        auto j = nlohmann::json::parse(body); int32_t user_id = j.at("user_id").get<int32_t>();
        { std::unique_lock lk(state_->ban_mu); state_->banned_users.insert(user_id); }
        std::shared_ptr<User> user;
        { std::shared_lock lk(state_->users_mu); auto it = state_->users.find(user_id); if (it != state_->users.end()) user = it->second; }
        if (user) {
            { Message m; m.type=MessageType::Chat; m.user=0; m.content="你已被管理员封禁。"; user->try_send(ServerCommand::make_message(m)); }
            std::shared_ptr<Room> rm; { std::shared_lock lk(user->room_mu); rm = user->room; }
            if (rm) { if (rm->on_user_leave(*user)) { std::unique_lock lk(state_->rooms_mu); state_->rooms.erase(rm->id.to_string()); } }
            { std::unique_lock lk(state_->users_mu); state_->users.erase(user_id); }
        }
        state_->save_bans();
        spdlog::info("Admin banned user {}", user_id);
        res.result(http::status::ok); res.body() = R"({"ok":true})";
    } catch (const std::exception& e) { res.result(http::status::bad_request); res.body() = nlohmann::json({{"error",e.what()}}).dump(); }
}

void RequestHandler::handle_admin_unban_user(const std::string& body, http::response<http::string_body>& res) {
    try {
        auto j = nlohmann::json::parse(body); int32_t user_id = j.at("user_id").get<int32_t>();
        { std::unique_lock lk(state_->ban_mu); state_->banned_users.erase(user_id); }
        state_->save_bans();
        spdlog::info("Admin unbanned user {}", user_id);
        res.result(http::status::ok); res.body() = R"({"ok":true})";
    } catch (const std::exception& e) { res.result(http::status::bad_request); res.body() = nlohmann::json({{"error",e.what()}}).dump(); }
}

void RequestHandler::handle_admin_banned_list(http::response<http::string_body>& res) {
    nlohmann::json arr = nlohmann::json::array();
    { std::shared_lock lk(state_->ban_mu); for (auto id : state_->banned_users) arr.push_back(id); }
    res.result(http::status::ok); res.body() = arr.dump();
}

void RequestHandler::handle_admin_page(http::response<http::string_body>& res) {
    res.set(http::field::content_type, "text/html; charset=utf-8");
    res.result(http::status::ok); res.body() = get_admin_html();
}

// ═══════════════════════════════════════════════════════════════════════
// Admin panel HTML — all Chinese
// ═══════════════════════════════════════════════════════════════════════
const char* get_admin_html() {
    return R"HTML(<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phira MP 后台管理</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#0f0f23;color:#e0e0e0;min-height:100vh}
.container{max-width:900px;margin:0 auto;padding:20px}
h1{text-align:center;color:#7c83ff;margin-bottom:20px;font-size:1.6em}
.login-box{background:#1a1a3e;border-radius:12px;padding:30px;margin-bottom:20px;text-align:center}
.login-box input{padding:10px 16px;border:1px solid #333;border-radius:8px;background:#0f0f23;color:#e0e0e0;font-size:14px;width:250px;margin-right:10px}
.login-box button{padding:10px 20px;background:#7c83ff;border:none;border-radius:8px;color:#fff;cursor:pointer;font-size:14px}
.login-box button:hover{background:#6b72ee}
.section{background:#1a1a3e;border-radius:12px;padding:20px;margin-bottom:16px}
.section h2{color:#7c83ff;margin-bottom:12px;font-size:1.15em;border-bottom:1px solid #2a2a5e;padding-bottom:8px}
.row{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
.row input,.row select{padding:8px 12px;border:1px solid #333;border-radius:6px;background:#0f0f23;color:#e0e0e0;font-size:13px;flex:1;min-width:120px}
.btn{padding:8px 16px;border:none;border-radius:6px;color:#fff;cursor:pointer;font-size:13px;white-space:nowrap}
.btn-blue{background:#3b82f6}.btn-blue:hover{background:#2563eb}
.btn-red{background:#ef4444}.btn-red:hover{background:#dc2626}
.btn-green{background:#22c55e}.btn-green:hover{background:#16a34a}
.btn-yellow{background:#eab308;color:#000}.btn-yellow:hover{background:#ca8a04}
#status{margin-top:8px;padding:10px;border-radius:6px;display:none;font-size:13px}
.ok{background:#16332e;color:#4ade80;display:block!important}
.err{background:#3b1c1c;color:#f87171;display:block!important}
#rooms{margin-top:10px}
.room-card{background:#12122e;border:1px solid #2a2a5e;border-radius:8px;padding:14px;margin-bottom:8px}
.room-card h3{color:#c084fc;margin-bottom:6px;font-size:1em}
.room-card .info{font-size:12px;color:#999;line-height:1.6}
.room-card .actions{margin-top:8px;display:flex;gap:6px;flex-wrap:wrap}
.room-card .actions button{font-size:11px;padding:4px 10px}
#banned-list{margin-top:8px;font-size:13px;color:#999}
.sse-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.sse-on{background:#4ade80}.sse-off{background:#f87171}
</style>
</head>
<body>
<div class="container">
<h1>Phira MP 后台管理面板</h1>

<div class="login-box" id="login-box">
  <input type="password" id="pw" placeholder="请输入管理密码">
  <button onclick="doLogin()">登 录</button>
</div>

<div id="main" style="display:none">
  <div class="section">
    <h2><span class="sse-dot sse-off" id="sse-dot"></span> 房间列表（实时）</h2>
    <div class="row">
      <button class="btn btn-blue" onclick="refreshRooms()">刷新房间</button>
    </div>
    <div id="rooms"></div>
  </div>

  <div class="section">
    <h2>创建房间</h2>
    <div class="row">
      <input id="new-room" placeholder="房间名称">
      <button class="btn btn-green" onclick="createRoom()">创 建</button>
    </div>
  </div>

  <div class="section">
    <h2>封禁管理</h2>
    <div class="row">
      <input id="ban-id" placeholder="用户 ID" type="number">
      <button class="btn btn-red" onclick="banUser()">封 禁</button>
      <button class="btn btn-yellow" onclick="unbanUser()">解 封</button>
      <button class="btn btn-blue" onclick="loadBanned()">查看封禁列表</button>
    </div>
    <div id="banned-list"></div>
  </div>

  <div id="status"></div>
</div>
</div>

<script>
let PW='';
const API=location.origin;
const STATE_MAP={"SELECTING_CHART":"选曲中","WAITING_FOR_READY":"等待准备","PLAYING":"游戏中"};
function doLogin(){PW=document.getElementById('pw').value;document.getElementById('login-box').style.display='none';document.getElementById('main').style.display='block';refreshRooms();connectSSE();}
function hdr(){return{'Content-Type':'application/json','X-Admin-Password':PW};}
function show(msg,ok){const s=document.getElementById('status');s.textContent=msg;s.className=ok?'ok':'err';setTimeout(()=>{s.style.display='none';},3000);}

async function api(method,path,body){
  try{const r=await fetch(API+path,{method,headers:hdr(),body:body?JSON.stringify(body):undefined});
  const j=await r.json();if(!r.ok)throw new Error(j.error||'请求失败');return j;}
  catch(e){show(e.message,false);throw e;}}

async function refreshRooms(){
  try{const rooms=await api('GET','/api/rooms/info');renderRooms(rooms);}catch(e){}}

function renderRooms(rooms){
  const c=document.getElementById('rooms');c.innerHTML='';
  if(!rooms.length){c.innerHTML='<div style="color:#666;font-size:13px">暂无房间</div>';return;}
  rooms.forEach(r=>{
    const d=document.createElement('div');d.className='room-card';
    const users=r.data.users||[];
    const stateText=STATE_MAP[r.data.state]||r.data.state;
    d.innerHTML=`<h3>${r.name}</h3>
      <div class="info">房主: ${r.data.host} | 用户: ${users.join(', ')||'无'} | 状态: ${stateText}<br>
      已锁定: ${r.data.lock?'是':'否'} | 轮换: ${r.data.cycle?'是':'否'} | 谱面: ${r.data.chart||'无'}</div>
      <div class="actions">
        <button class="btn btn-red" onclick="deleteRoom('${r.name}')">删除房间</button>
        ${users.map(u=>`<button class="btn btn-yellow" onclick="kickUser(${u},'${r.name}')">踢出 ${u}</button>`).join('')}
      </div>`;
    c.appendChild(d);});
}

async function createRoom(){const n=document.getElementById('new-room').value;if(!n)return;
  try{await api('POST','/api/admin/create-room',{name:n});show('房间已创建',true);refreshRooms();}catch(e){}}
async function deleteRoom(n){if(!confirm('确定要删除房间 '+n+' 吗？'))return;
  try{await api('POST','/api/admin/delete-room',{name:n});show('房间已删除',true);refreshRooms();}catch(e){}}
async function kickUser(uid,room){
  try{await api('POST','/api/admin/kick-user',{user_id:uid,room});show('用户已被踢出',true);refreshRooms();}catch(e){}}
async function banUser(){const id=parseInt(document.getElementById('ban-id').value);if(!id)return;
  try{await api('POST','/api/admin/ban-user',{user_id:id});show('用户已被封禁',true);loadBanned();}catch(e){}}
async function unbanUser(){const id=parseInt(document.getElementById('ban-id').value);if(!id)return;
  try{await api('POST','/api/admin/unban-user',{user_id:id});show('用户已解封',true);loadBanned();}catch(e){}}
async function loadBanned(){
  try{const list=await api('GET','/api/admin/banned');
  document.getElementById('banned-list').textContent='已封禁用户: '+(list.length?list.join(', '):'无');}catch(e){}}

function connectSSE(){
  const dot=document.getElementById('sse-dot');
  const es=new EventSource(API+'/api/rooms/listen');
  es.onopen=()=>{dot.className='sse-dot sse-on';};
  es.onerror=()=>{dot.className='sse-dot sse-off';setTimeout(()=>connectSSE(),3000);};
  es.addEventListener('create_room',e=>{refreshRooms();});
  es.addEventListener('update_room',e=>{refreshRooms();});
  es.addEventListener('join_room',e=>{refreshRooms();});
  es.addEventListener('leave_room',e=>{refreshRooms();});
  es.addEventListener('new_round',e=>{refreshRooms();});
}
</script>
</body>
</html>)HTML";
}
