#include "session.h"
#include "room.h"
#include "server.h"
#include "http_client.h"
#include "ban_manager.h"
#include "web_server.h"
#include "ws_server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>

static const char* HOST_URL = "https://phira.5wyxi.com";

// ══════════════════════════════════════════════════════════════════════
// SendQueue
// ══════════════════════════════════════════════════════════════════════

void SendQueue::push(ServerCommand cmd) {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (closed_.load()) return;
        queue_.push(std::move(cmd));
    }
    cv_.notify_one();
}

bool SendQueue::pop(ServerCommand& cmd, int timeout_ms) {
    std::unique_lock<std::mutex> lock(mtx_);
    if (cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                     [this] { return !queue_.empty() || closed_.load(); })) {
        if (closed_.load() && queue_.empty()) return false;
        cmd = std::move(queue_.front());
        queue_.pop();
        return true;
    }
    return false;
}

void SendQueue::close() {
    closed_.store(true);
    cv_.notify_all();
}

bool SendQueue::is_closed() const {
    return closed_.load();
}

// ══════════════════════════════════════════════════════════════════════
// User
// ══════════════════════════════════════════════════════════════════════

User::User(int32_t id_, std::string name_, Language lang_, std::shared_ptr<ServerState> srv)
    : id(id_), name(std::move(name_)), lang(std::move(lang_)), server(std::move(srv)) {}

UserInfo User::to_info() const {
    UserInfo info;
    info.id = id;
    info.name = name;
    info.monitor = monitor.load();
    return info;
}

bool User::can_monitor() const {
    for (auto m : server->config.monitors) {
        if (m == id) return true;
    }
    return false;
}

void User::set_session(std::weak_ptr<Session> s) {
    std::unique_lock lock(session_mtx);
    session = std::move(s);
    // Clear dangle mark
    std::lock_guard dlock(dangle_mtx);
    dangle_mark.reset();
}

void User::try_send(ServerCommand cmd) const {
    std::shared_lock lock(session_mtx);
    auto s = session.lock();
    if (s) {
        s->try_send(std::move(cmd));
    } else {
        std::cerr << "[user] sending to dangling user " << id << std::endl;
    }
}

void User::dangle() {
    std::cerr << "[user] user " << id << " dangling" << std::endl;

    // If playing, abort immediately
    auto rm = get_room();
    if (rm) {
        std::shared_lock sl(rm->state_mtx);
        if (rm->state.type == InternalRoomStateType::Playing) {
            std::cerr << "[user] lost connection on playing, aborting user " << id << std::endl;
            sl.unlock();
            {
                std::unique_lock lock(server->users_mtx);
                server->users.erase(id);
            }
            // Clear room ref before on_user_leave
            {
                std::unique_lock rl(room_mtx);
                room.reset();
            }
            if (rm->on_user_leave(*this)) {
                std::unique_lock lock(server->rooms_mtx);
                server->rooms.erase(rm->id.to_string());
            }
            return;
        }
    }

    // Set up dangle mark and start timeout
    auto mark = std::make_shared<int>(0);
    {
        std::lock_guard lock(dangle_mtx);
        dangle_mark = mark;
    }

    // Capture what we need for the cleanup thread
    auto self_id = id;
    auto self_server = server;

    // weak_ptr to self for the timeout thread
    // We need shared_from_this but User might not be in a shared_ptr context always
    // Instead, just use the dangle mark for timeout check

    std::thread([mark, self_id, self_server, rm_copy = rm]() mutable {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        // If mark use_count > 1, the user hasn't reconnected (mark still stored in dangle_mark)
        if (mark.use_count() > 1) {
            std::cerr << "[user] dangle timeout for user " << self_id << std::endl;
            // Remove from users
            std::shared_ptr<User> user_ptr;
            {
                std::shared_lock lock(self_server->users_mtx);
                auto it = self_server->users.find(self_id);
                if (it != self_server->users.end()) user_ptr = it->second;
            }
            if (user_ptr) {
                auto rm2 = user_ptr->get_room();
                if (rm2) {
                    {
                        std::unique_lock rl(user_ptr->room_mtx);
                        user_ptr->room.reset();
                    }
                    {
                        std::unique_lock lock(self_server->users_mtx);
                        self_server->users.erase(self_id);
                    }
                    if (rm2->on_user_leave(*user_ptr)) {
                        std::unique_lock lock(self_server->rooms_mtx);
                        self_server->rooms.erase(rm2->id.to_string());
                    }
                } else {
                    std::unique_lock lock(self_server->users_mtx);
                    self_server->users.erase(self_id);
                }
            }
        }
    }).detach();
}

std::shared_ptr<Room> User::get_room() const {
    std::shared_lock lock(room_mtx);
    return room;
}

void User::set_room(std::shared_ptr<Room> r) {
    std::unique_lock lock(room_mtx);
    room = std::move(r);
}

void User::clear_room() {
    std::unique_lock lock(room_mtx);
    room.reset();
}

// ══════════════════════════════════════════════════════════════════════
// Session
// ══════════════════════════════════════════════════════════════════════

Session::Session(MpUuid sid, int fd, uint8_t ver, std::shared_ptr<ServerState> /*server*/)
    : id(sid), version_(ver), socket_fd(fd)
{
    last_recv = std::chrono::steady_clock::now();
}

Session::~Session() {
    stop();
}

void Session::try_send(ServerCommand cmd) {
    send_queue.push(std::move(cmd));
}

void Session::stop() {
    if (!alive.exchange(false)) return;
    send_queue.close();
    if (socket_fd >= 0) {
        shutdown(socket_fd, SHUT_RDWR);
        close(socket_fd);
        socket_fd = -1;
    }
}

void Session::update_last_recv() {
    std::lock_guard<std::mutex> lock(last_recv_mtx);
    last_recv = std::chrono::steady_clock::now();
}

// ── Send loop: serialize and write packets to socket ─────────────────
void Session::send_loop() {
    ServerCommand cmd;
    std::vector<uint8_t> buf;
    uint8_t len_buf[5];

    while (alive.load()) {
        if (!send_queue.pop(cmd, 200)) continue;

        buf.clear();
        BinaryWriter writer(buf);
        cmd.write_binary(writer);

        // ULEB128 length prefix
        uint32_t len = (uint32_t)buf.size();
        int n = 0;
        uint32_t x = len;
        do {
            len_buf[n] = (uint8_t)(x & 0x7F);
            x >>= 7;
            if (x > 0) len_buf[n] |= 0x80;
            n++;
        } while (x > 0);

        // Write length prefix + payload
        int fd = socket_fd;
        if (fd < 0) break;

        auto write_all = [fd](const void* data, size_t sz) -> bool {
            const uint8_t* p = (const uint8_t*)data;
            size_t sent = 0;
            while (sent < sz) {
                ssize_t r = ::send(fd, p + sent, sz - sent, MSG_NOSIGNAL);
                if (r <= 0) return false;
                sent += (size_t)r;
            }
            return true;
        };

        if (!write_all(len_buf, n) || !write_all(buf.data(), buf.size())) {
            std::cerr << "[session] send failed for " << id.str() << std::endl;
            break;
        }
    }
}

// ── Recv loop: read packets, decode, and process commands ────────────
void Session::recv_loop(std::shared_ptr<ServerState> server) {
    int fd = socket_fd;
    auto read_all = [&](void* data, size_t sz) -> bool {
        uint8_t* p = (uint8_t*)data;
        size_t got = 0;
        while (got < sz) {
            ssize_t r = ::recv(fd, p + got, sz - got, 0);
            if (r <= 0) return false;
            got += (size_t)r;
        }
        return true;
    };

    bool authenticated = false;

    while (alive.load()) {
        // Read ULEB128 length
        uint32_t len = 0;
        int shift = 0;
        while (true) {
            uint8_t byte;
            if (!read_all(&byte, 1)) goto disconnect;
            len |= (uint32_t)(byte & 0x7F) << shift;
            shift += 7;
            if ((byte & 0x80) == 0) break;
            if (shift > 32) goto disconnect;
        }
        if (len > 2 * 1024 * 1024) goto disconnect;

        // Read payload
        std::vector<uint8_t> buf(len);
        if (len > 0 && !read_all(buf.data(), len)) goto disconnect;

        update_last_recv();

        // Decode
        ClientCommand cmd;
        try {
            BinaryReader reader(buf);
            cmd = ClientCommand::read_binary(reader);
        } catch (const std::exception& e) {
            std::cerr << "[session] invalid packet from " << id.str() << ": " << e.what() << std::endl;
            goto disconnect;
        }

        // Handle Ping immediately
        if (cmd.type == ClientCommandType::Ping) {
            try_send(ServerCommand::pong());
            continue;
        }

        // Handle authentication
        if (!authenticated) {
            if (cmd.type == ClientCommandType::Authenticate) {
                handle_authenticate(cmd.token, server);
                if (user) {
                    authenticated = true;
                } else {
                    // Auth failed, session will be cleaned up
                    goto disconnect;
                }
            } else {
                std::cerr << "[session] packet before authentication, ignoring" << std::endl;
            }
            continue;
        }

        // Process authenticated commands
        process_command(cmd);
    }

disconnect:
    if (alive.load()) {
        std::cerr << "[session] connection lost: " << id.str() << std::endl;
        server->push_lost_connection(id);
    }
}

// ── Heartbeat loop: check for disconnect timeout ─────────────────────
void Session::heartbeat_loop(std::shared_ptr<ServerState> server) {
    static constexpr auto DISCONNECT_TIMEOUT = std::chrono::seconds(10);

    while (alive.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        if (!alive.load()) break;

        std::chrono::steady_clock::time_point lr;
        {
            std::lock_guard<std::mutex> lock(last_recv_mtx);
            lr = last_recv;
        }

        if (std::chrono::steady_clock::now() - lr > DISCONNECT_TIMEOUT) {
            std::cerr << "[session] heartbeat timeout: " << id.str() << std::endl;
            server->push_lost_connection(id);
            break;
        }
    }
}

// ── Authentication handler ───────────────────────────────────────────
void Session::handle_authenticate(const std::string& token, std::shared_ptr<ServerState> server) {

    std::cerr << "[session] " << id.str() << ": authenticate " << token << std::endl;

    // Fetch user info from API
    std::string url = std::string(HOST_URL) + "/me";
    auto resp = HttpClient::get(url, token);
    if (!resp.ok()) {
        std::cerr << "[session] failed to fetch user info: HTTP " << resp.status_code << std::endl;
        try_send(ServerCommand::authenticate_err("failed to fetch info"));
        return;
    }

    // Parse response
    int32_t user_id;
    std::string user_name, user_lang_str;
    try {
        user_id = SimpleJson::get_int(resp.body, "id");
        user_name = SimpleJson::get_string(resp.body, "name");
        user_lang_str = SimpleJson::get_string(resp.body, "language");
    } catch (const std::exception& e) {
        std::cerr << "[session] failed to parse user info: " << e.what() << std::endl;
        try_send(ServerCommand::authenticate_err("failed to parse info"));
        return;
    }

    Language lang(L10n::parse_language(user_lang_str));

    std::cerr << "[session] " << id.str() << " <- id=" << user_id
              << " name=" << user_name << " lang=" << user_lang_str << std::endl;

    // Check if user is banned
    if (BanManager::instance().is_banned(user_id)) {
        std::cerr << "[session] user " << user_id << " is banned" << std::endl;
        try_send(ServerCommand::authenticate_err("你已被封禁，无法连接服务器。如有疑问请联系管理员，QQ群：1049578201"));
        return;
    }

    // Check if user already exists (reconnect)
    {
        std::unique_lock lock(server->users_mtx);
        auto it = server->users.find(user_id);
        if (it != server->users.end()) {
            std::cerr << "[session] reconnect for user " << user_id << std::endl;
            user = it->second;
            user->set_session(weak_from_this());
        } else {
            user = std::make_shared<User>(user_id, user_name, lang, server);
            user->set_session(weak_from_this());
            server->users[user_id] = user;
        }
    }

    // Build auth response
    std::optional<ClientRoomState> room_state;
    auto rm = user->get_room();
    if (rm) {
        room_state = rm->client_state(*user);
    }
    try_send(ServerCommand::authenticate_ok(user->to_info(), std::move(room_state)));

    // Send welcome message with available rooms and QQ group
    {
        std::ostringstream welcome;
        welcome << "欢迎来到 Phira 多人游戏服务器！\n";
        welcome << "QQ群：1049578201\n";

        // List available rooms (not Playing, not WaitingForReady)
        std::vector<std::pair<std::string, int>> available_rooms;
        {
            std::shared_lock lock(server->rooms_mtx);
            for (auto& [name, room] : server->rooms) {
                std::shared_lock sl(room->state_mtx);
                if (room->state.type == InternalRoomStateType::SelectChart && !room->is_locked()) {
                    auto u = room->users();
                    available_rooms.emplace_back(name, (int)u.size());
                }
            }
        }

        if (!available_rooms.empty()) {
            welcome << "当前可加入的房间：\n";
            for (auto& [name, count] : available_rooms) {
                welcome << "  " << name << " (" << count << "/8)\n";
            }
        } else {
            welcome << "当前暂无可加入的房间，你可以创建一个新房间。\n";
        }

        try_send(ServerCommand::msg(Message::chat(0, welcome.str())));
    }
}

// ── Command processor (mirrors Rust's process function) ──────────────
void Session::process_command(const ClientCommand& cmd) {
    auto& lang = user->lang;

    switch (cmd.type) {
    case ClientCommandType::Ping:
        // Already handled in recv_loop
        break;

    case ClientCommandType::Authenticate:
        try_send(ServerCommand::authenticate_err("repeated authenticate"));
        break;

    case ClientCommandType::Chat: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::Chat, "no room"));
            break;
        }
        rm->send_as(*user, cmd.message);
        try_send(ServerCommand::simple_ok(ServerCommandType::Chat));
        break;
    }

    case ClientCommandType::Touches: {
        auto rm = user->get_room();
        if (!rm) break; // silently ignore
        if (rm->is_live()) {
            if (cmd.frames && !cmd.frames->empty()) {
                float t = cmd.frames->back().time;
                uint32_t bits;
                memcpy(&bits, &t, sizeof(bits));
                user->game_time.store(bits);
            }
            rm->broadcast_monitors(ServerCommand::touches(user->id, cmd.frames));

            // WSS: broadcast touch frames as JSON
            if (g_ws_server && cmd.frames && !cmd.frames->empty()) {
                std::ostringstream oss;
                oss << "[";
                bool first = true;
                for (auto& frame : *cmd.frames) {
                    if (!first) oss << ",";
                    first = false;
                    oss << "{\"time\":" << frame.time << ",\"points\":[";
                    bool pfirst = true;
                    for (auto& [id, pos] : frame.points) {
                        if (!pfirst) oss << ",";
                        pfirst = false;
                        oss << "{\"id\":" << (int)id
                            << ",\"x\":" << pos.x()
                            << ",\"y\":" << pos.y() << "}";
                    }
                    oss << "]}";
                }
                oss << "]";
                g_ws_server->broadcast_touches(rm->id.to_string(), user->id, oss.str());
            }
        }
        // No response for touches
        break;
    }

    case ClientCommandType::Judges: {
        auto rm = user->get_room();
        if (!rm) break;
        if (rm->is_live()) {
            rm->broadcast_monitors(ServerCommand::judges_cmd(user->id, cmd.judges));

            // WSS: broadcast judge events as JSON
            if (g_ws_server && cmd.judges && !cmd.judges->empty()) {
                std::ostringstream oss;
                oss << "[";
                bool first = true;
                for (auto& je : *cmd.judges) {
                    if (!first) oss << ",";
                    first = false;
                    std::string jname;
                    switch (je.judgement) {
                        case Judgement::Perfect:     jname = "Perfect"; break;
                        case Judgement::Good:        jname = "Good"; break;
                        case Judgement::Bad:         jname = "Bad"; break;
                        case Judgement::Miss:        jname = "Miss"; break;
                        case Judgement::HoldPerfect: jname = "HoldPerfect"; break;
                        case Judgement::HoldGood:    jname = "HoldGood"; break;
                    }
                    oss << "{\"time\":" << je.time
                        << ",\"line_id\":" << je.line_id
                        << ",\"note_id\":" << je.note_id
                        << ",\"judgement\":\"" << jname << "\"}";
                }
                oss << "]";
                g_ws_server->broadcast_judges(rm->id.to_string(), user->id, oss.str());
            }
        }
        break;
    }

    case ClientCommandType::CreateRoom: {
        auto existing_room = user->get_room();
        if (existing_room) {
            try_send(ServerCommand::simple_err(ServerCommandType::CreateRoom, "already in room"));
            break;
        }

        auto& rid = cmd.room_id;
        {
            std::unique_lock lock(user->server->rooms_mtx);
            if (user->server->rooms.count(rid.to_string())) {
                try_send(ServerCommand::simple_err(ServerCommandType::CreateRoom,
                                                    tl(lang, "create-id-occupied")));
                break;
            }
            auto new_room = std::make_shared<Room>(rid, std::weak_ptr<User>(user));
            user->server->rooms[rid.to_string()] = new_room;
            new_room->send(Message::create_room(user->id));
            user->set_room(new_room);
        }
        std::cerr << "[session] user " << user->id << " create room " << rid.to_string() << std::endl;
        try_send(ServerCommand::simple_ok(ServerCommandType::CreateRoom));
        // SSE: create_room
        if (g_web_server) {
            std::ostringstream oss;
            oss << "{\"room\":\"" << rid.to_string() << "\",\"data\":{"
                << "\"host\":" << user->id
                << ",\"users\":[" << user->id << "]"
                << ",\"lock\":false,\"cycle\":false,\"chart\":null"
                << ",\"state\":\"SELECTING_CHART\",\"playing_users\":[],\"rounds\":[]}}";
            g_web_server->broadcast_sse("create_room", oss.str());
        }
        break;
    }

    case ClientCommandType::JoinRoom: {
        auto existing_room = user->get_room();
        if (existing_room) {
            try_send(ServerCommand::join_room_err("already in room"));
            break;
        }
        std::shared_ptr<Room> target_room;
        {
            std::shared_lock lock(user->server->rooms_mtx);
            auto it = user->server->rooms.find(cmd.room_id.to_string());
            if (it != user->server->rooms.end()) target_room = it->second;
        }
        if (!target_room) {
            try_send(ServerCommand::join_room_err("room not found"));
            break;
        }
        if (target_room->is_locked()) {
            try_send(ServerCommand::join_room_err(tl(lang, "join-room-locked")));
            break;
        }
        {
            std::shared_lock sl(target_room->state_mtx);
            if (target_room->state.type != InternalRoomStateType::SelectChart) {
                try_send(ServerCommand::join_room_err(tl(lang, "join-game-ongoing")));
                break;
            }
        }
        bool wants_monitor = cmd.monitor;
        if (wants_monitor && !user->can_monitor()) {
            try_send(ServerCommand::join_room_err(tl(lang, "join-cant-monitor")));
            break;
        }
        if (!target_room->add_user(std::weak_ptr<User>(user), wants_monitor)) {
            try_send(ServerCommand::join_room_err(tl(lang, "join-room-full")));
            break;
        }
        std::cerr << "[session] user " << user->id << " join room "
                  << cmd.room_id.to_string() << " monitor=" << wants_monitor << std::endl;
        user->monitor.store(wants_monitor);
        if (wants_monitor) {
            bool was_live = target_room->live.exchange(true);
            if (!was_live) {
                std::cerr << "[session] room " << cmd.room_id.to_string() << " goes live" << std::endl;
            }
        }
        target_room->broadcast(ServerCommand::on_join_room(user->to_info()));
        target_room->send(Message::join_room(user->id, user->name));
        user->set_room(target_room);

        // Build join response
        JoinRoomResponse jr;
        jr.state = target_room->client_room_state();
        auto u = target_room->users();
        auto m = target_room->monitors();
        for (auto& usr : u) jr.users.push_back(usr->to_info());
        for (auto& usr : m) jr.users.push_back(usr->to_info());
        jr.live = target_room->is_live();
        try_send(ServerCommand::join_room_ok(std::move(jr)));
        // SSE: join_room
        if (g_web_server) {
            g_web_server->broadcast_sse("join_room",
                "{\"room\":\"" + cmd.room_id.to_string() + "\",\"user\":" + std::to_string(user->id) + "}");
        }
        break;
    }

    case ClientCommandType::LeaveRoom: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::LeaveRoom, "no room"));
            break;
        }
        std::cerr << "[session] user " << user->id << " leave room " << rm->id.to_string() << std::endl;
        user->clear_room();
        // SSE: leave_room
        if (g_web_server) {
            g_web_server->broadcast_sse("leave_room",
                "{\"room\":\"" + rm->id.to_string() + "\",\"user\":" + std::to_string(user->id) + "}");
        }
        if (rm->on_user_leave(*user)) {
            std::unique_lock lock(user->server->rooms_mtx);
            user->server->rooms.erase(rm->id.to_string());
        }
        try_send(ServerCommand::simple_ok(ServerCommandType::LeaveRoom));
        break;
    }

    case ClientCommandType::LockRoom: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::LockRoom, "no room"));
            break;
        }
        if (!rm->check_host(*user)) {
            try_send(ServerCommand::simple_err(ServerCommandType::LockRoom, "only host can do this"));
            break;
        }
        std::cerr << "[session] user " << user->id << " lock room " << rm->id.to_string()
                  << " lock=" << cmd.flag << std::endl;
        rm->locked.store(cmd.flag);
        rm->send(Message::lock_room(cmd.flag));
        rm->on_state_change();  // FIX: fire SSE update_room event
        try_send(ServerCommand::simple_ok(ServerCommandType::LockRoom));
        break;
    }

    case ClientCommandType::CycleRoom: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::CycleRoom, "no room"));
            break;
        }
        if (!rm->check_host(*user)) {
            try_send(ServerCommand::simple_err(ServerCommandType::CycleRoom, "only host can do this"));
            break;
        }
        std::cerr << "[session] user " << user->id << " cycle room " << rm->id.to_string()
                  << " cycle=" << cmd.flag << std::endl;
        rm->cycle.store(cmd.flag);
        rm->send(Message::cycle_room(cmd.flag));
        rm->on_state_change();  // FIX: fire SSE update_room event
        try_send(ServerCommand::simple_ok(ServerCommandType::CycleRoom));
        break;
    }

    case ClientCommandType::SelectChart: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::SelectChart, "no room"));
            break;
        }
        {
            std::shared_lock sl(rm->state_mtx);
            if (rm->state.type != InternalRoomStateType::SelectChart) {
                try_send(ServerCommand::simple_err(ServerCommandType::SelectChart, "invalid state"));
                break;
            }
        }
        if (!rm->check_host(*user)) {
            try_send(ServerCommand::simple_err(ServerCommandType::SelectChart, "only host can do this"));
            break;
        }

        // Fetch chart info from API
        std::string url = std::string(HOST_URL) + "/chart/" + std::to_string(cmd.chart_id);
        auto resp = HttpClient::get(url);
        if (!resp.ok()) {
            try_send(ServerCommand::simple_err(ServerCommandType::SelectChart,
                                                "failed to fetch chart"));
            break;
        }

        Chart chart_info;
        try {
            chart_info.id = SimpleJson::get_int(resp.body, "id");
            chart_info.name = SimpleJson::get_string(resp.body, "name");
        } catch (const std::exception& e) {
            try_send(ServerCommand::simple_err(ServerCommandType::SelectChart,
                                                "failed to parse chart info"));
            break;
        }

        rm->send(Message::select_chart(user->id, chart_info.name, chart_info.id));
        {
            std::unique_lock cl(rm->chart_mtx);
            rm->chart = chart_info;
        }
        rm->on_state_change();
        try_send(ServerCommand::simple_ok(ServerCommandType::SelectChart));
        break;
    }

    case ClientCommandType::RequestStart: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::RequestStart, "no room"));
            break;
        }
        {
            std::shared_lock sl(rm->state_mtx);
            if (rm->state.type != InternalRoomStateType::SelectChart) {
                try_send(ServerCommand::simple_err(ServerCommandType::RequestStart, "invalid state"));
                break;
            }
        }
        if (!rm->check_host(*user)) {
            try_send(ServerCommand::simple_err(ServerCommandType::RequestStart, "only host can do this"));
            break;
        }
        {
            std::shared_lock cl(rm->chart_mtx);
            if (!rm->chart) {
                try_send(ServerCommand::simple_err(ServerCommandType::RequestStart,
                                                    tl(lang, "start-no-chart-selected")));
                break;
            }
        }
        std::cerr << "[session] room " << rm->id.to_string() << " wait for ready" << std::endl;
        rm->reset_game_time();
        rm->send(Message::game_start(user->id));
        {
            std::unique_lock sl(rm->state_mtx);
            std::set<int32_t> started;
            started.insert(user->id);
            rm->state = InternalRoomState::wait_for_ready(std::move(started));
        }
        rm->on_state_change();
        rm->check_all_ready();
        try_send(ServerCommand::simple_ok(ServerCommandType::RequestStart));
        break;
    }

    case ClientCommandType::Ready: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::Ready, "no room"));
            break;
        }
        {
            std::unique_lock sl(rm->state_mtx);
            if (rm->state.type == InternalRoomStateType::WaitForReady) {
                if (!rm->state.started.insert(user->id).second) {
                    try_send(ServerCommand::simple_err(ServerCommandType::Ready, "already ready"));
                    break;
                }
            } else {
                try_send(ServerCommand::simple_ok(ServerCommandType::Ready));
                break;
            }
        }
        rm->send(Message::ready(user->id));
        rm->check_all_ready();
        try_send(ServerCommand::simple_ok(ServerCommandType::Ready));
        break;
    }

    case ClientCommandType::CancelReady: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::CancelReady, "no room"));
            break;
        }
        {
            std::unique_lock sl(rm->state_mtx);
            if (rm->state.type == InternalRoomStateType::WaitForReady) {
                if (rm->state.started.erase(user->id) == 0) {
                    try_send(ServerCommand::simple_err(ServerCommandType::CancelReady, "not ready"));
                    break;
                }
                if (rm->check_host(*user)) {
                    // Host cancels → cancel the whole game
                    rm->send(Message::cancel_game(user->id));
                    rm->state = InternalRoomState::select_chart();
                    sl.unlock();
                    rm->on_state_change();
                } else {
                    rm->send(Message::cancel_ready(user->id));
                }
            }
        }
        try_send(ServerCommand::simple_ok(ServerCommandType::CancelReady));
        break;
    }

    case ClientCommandType::Played: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::Played, "no room"));
            break;
        }

        // Fetch record from API
        std::string url = std::string(HOST_URL) + "/record/" + std::to_string(cmd.chart_id);
        auto resp = HttpClient::get(url);
        if (!resp.ok()) {
            try_send(ServerCommand::simple_err(ServerCommandType::Played, "failed to fetch record"));
            break;
        }

        Record rec;
        try {
            rec.id = SimpleJson::get_int(resp.body, "id");
            rec.player = SimpleJson::get_int(resp.body, "player");
            rec.score = SimpleJson::get_int(resp.body, "score");
            rec.perfect = SimpleJson::get_int(resp.body, "perfect");
            rec.good = SimpleJson::get_int(resp.body, "good");
            rec.bad = SimpleJson::get_int(resp.body, "bad");
            rec.miss = SimpleJson::get_int(resp.body, "miss");
            rec.max_combo = SimpleJson::get_int(resp.body, "max_combo");
            rec.accuracy = SimpleJson::get_float(resp.body, "accuracy");
            rec.full_combo = SimpleJson::get_bool(resp.body, "full_combo");
            rec.std_dev = SimpleJson::get_float(resp.body, "std");
            rec.std_score = SimpleJson::get_float(resp.body, "std_score");
        } catch (const std::exception& e) {
            try_send(ServerCommand::simple_err(ServerCommandType::Played, "failed to parse record"));
            break;
        }

        if (rec.player != user->id) {
            try_send(ServerCommand::simple_err(ServerCommandType::Played, "invalid record"));
            break;
        }

        rm->send(Message::played(user->id, rec.score, rec.accuracy, rec.full_combo));

        {
            std::unique_lock sl(rm->state_mtx);
            if (rm->state.type == InternalRoomStateType::Playing) {
                if (rm->state.aborted.count(user->id)) {
                    try_send(ServerCommand::simple_err(ServerCommandType::Played, "aborted"));
                    break;
                }
                if (rm->state.results.count(user->id)) {
                    try_send(ServerCommand::simple_err(ServerCommandType::Played, "already uploaded"));
                    break;
                }
                rm->state.results[user->id] = rec;
            }
        }
        rm->check_all_ready();
        try_send(ServerCommand::simple_ok(ServerCommandType::Played));
        break;
    }

    case ClientCommandType::Abort: {
        auto rm = user->get_room();
        if (!rm) {
            try_send(ServerCommand::simple_err(ServerCommandType::Abort, "no room"));
            break;
        }
        {
            std::unique_lock sl(rm->state_mtx);
            if (rm->state.type == InternalRoomStateType::Playing) {
                if (rm->state.results.count(user->id)) {
                    try_send(ServerCommand::simple_err(ServerCommandType::Abort, "already uploaded"));
                    break;
                }
                if (!rm->state.aborted.insert(user->id).second) {
                    try_send(ServerCommand::simple_err(ServerCommandType::Abort, "aborted"));
                    break;
                }
            }
        }
        rm->send(Message::abort_msg(user->id));
        rm->check_all_ready();
        try_send(ServerCommand::simple_ok(ServerCommandType::Abort));
        break;
    }
    }
}
