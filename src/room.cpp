#include "room.hpp"
#include "session.hpp"
#include <spdlog/spdlog.h>
#include <cmath>
#include <random>
#include <algorithm>
#include <cstring>

// ── InternalRoomState ─────────────────────────────────────────────────
RoomState InternalRoomState::to_client(std::optional<int32_t> chart) const {
    RoomState rs;
    switch (type) {
    case Type::SelectChart: rs.type = RoomStateType::SelectChart; rs.chart_id = chart; break;
    case Type::WaitForReady: rs.type = RoomStateType::WaitingForReady; break;
    case Type::Playing: rs.type = RoomStateType::Playing; break;
    }
    return rs;
}
StrippedRoomState InternalRoomState::to_stripped() const {
    switch (type) {
    case Type::SelectChart: return StrippedRoomState::SelectingChart;
    case Type::WaitForReady: return StrippedRoomState::WaitingForReady;
    case Type::Playing: return StrippedRoomState::Playing;
    }
    return StrippedRoomState::SelectingChart;
}

// ── Room ──────────────────────────────────────────────────────────────
Room::Room(const RoomId& rid, std::weak_ptr<User> h) : id(rid), host(h) { users_.push_back(h); }

RoomState Room::client_room_state() {
    std::shared_lock l1(state_mu), l2(chart_mu);
    std::optional<int32_t> cid; if (chart) cid = chart->id;
    return state.to_client(cid);
}

ClientRoomState Room::client_state(const User& u) {
    ClientRoomState cs; cs.id = id; cs.state = client_room_state();
    cs.live = is_live(); cs.locked = is_locked(); cs.cycle = is_cycle();
    { std::shared_lock lk(host_mu); auto h = host.lock(); cs.is_host = h && h->id == u.id; }
    { std::shared_lock lk(state_mu); if (state.type == InternalRoomState::Type::WaitForReady) cs.is_ready = state.started.count(u.id) > 0; }
    for (auto& p : get_users()) cs.users[p->id] = p->to_info();
    for (auto& p : get_monitors()) cs.users[p->id] = p->to_info();
    return cs;
}

bool Room::add_user(std::weak_ptr<User> u, bool mon) {
    if (mon) { std::unique_lock lk(monitors_mu_);
        monitors_.erase(std::remove_if(monitors_.begin(), monitors_.end(), [](auto& w){ return w.expired(); }), monitors_.end());
        monitors_.push_back(u); return true;
    } else { std::unique_lock lk(users_mu_);
        users_.erase(std::remove_if(users_.begin(), users_.end(), [](auto& w){ return w.expired(); }), users_.end());
        if (users_.size() >= ROOM_MAX_USERS) return false;
        users_.push_back(u); return true;
    }
}

std::vector<std::shared_ptr<User>> Room::get_users() {
    std::shared_lock lk(users_mu_); std::vector<std::shared_ptr<User>> r;
    for (auto& w : users_) {
        if (auto s = w.lock()) r.push_back(s);
    }
    return r;
}
std::vector<std::shared_ptr<User>> Room::get_monitors() {
    std::shared_lock lk(monitors_mu_); std::vector<std::shared_ptr<User>> r;
    for (auto& w : monitors_) {
        if (auto s = w.lock()) r.push_back(s);
    }
    return r;
}
void Room::check_host_throw(const User& u) {
    std::shared_lock lk(host_mu); auto h = host.lock();
    if (!h || h->id != u.id) throw std::runtime_error("only host can do this");
}
void Room::send_msg(const Message& m) { broadcast(ServerCommand::make_message(m)); }
void Room::broadcast(const ServerCommand& c) {
    for (auto& u : get_users()) u->try_send(c);
    for (auto& m : get_monitors()) m->try_send(c);
}
void Room::broadcast_monitors(const ServerCommand& c) { for (auto& m : get_monitors()) m->try_send(c); }
void Room::send_as(const User& u, const std::string& content) {
    Message m; m.type = MessageType::Chat; m.user = u.id; m.content = content; send_msg(m);
}
void Room::on_state_change() { broadcast(ServerCommand::make_change_state(client_room_state())); }

// ── FIX: on_user_leave now takes non-const ref (was const User& + const_cast) ──
bool Room::on_user_leave(User& u) {
    { Message m; m.type = MessageType::LeaveRoom; m.user = u.id; m.name = u.name; send_msg(m); }
    { std::unique_lock lk(u.room_mu); u.room.reset(); }
    if (u.monitor.load(std::memory_order_seq_cst)) {
        std::unique_lock lk(monitors_mu_);
        monitors_.erase(std::remove_if(monitors_.begin(), monitors_.end(), [&](auto& w){ auto s = w.lock(); return !s || s->id == u.id; }), monitors_.end());
    } else {
        std::unique_lock lk(users_mu_);
        users_.erase(std::remove_if(users_.begin(), users_.end(), [&](auto& w){ auto s = w.lock(); return !s || s->id == u.id; }), users_.end());
    }
    bool was_host = false;
    { std::shared_lock lk(host_mu); auto h = host.lock(); was_host = h && h->id == u.id; }
    if (was_host) {
        spdlog::info("host disconnected!");
        auto users = get_users();
        if (users.empty()) { spdlog::info("all disconnected, dropping room"); return true; }
        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<size_t> dist(0, users.size()-1);
        auto nh = users[dist(rng)];
        { std::unique_lock lk(host_mu); host = nh; }
        Message m; m.type = MessageType::NewHost; m.user = nh->id; send_msg(m);
        nh->try_send(ServerCommand::make_change_host(true));
    }
    check_all_ready();
    return false;
}

void Room::reset_game_time() {
    uint32_t neg; float ni = -std::numeric_limits<float>::infinity(); std::memcpy(&neg, &ni, 4);
    for (auto& u : get_users()) u->game_time.store(neg, std::memory_order_seq_cst);
}

// ── FIX: check_all_ready — re-check state after re-acquiring lock ────
// Previously, two threads could both see "all ready" and both transition,
// leading to double state transitions and corrupted rounds data.
void Room::check_all_ready() {
    std::unique_lock lk(state_mu);
    if (state.type == InternalRoomState::Type::WaitForReady) {
        auto us = get_users(), ms = get_monitors();
        bool all = true;
        for (auto& u : us) if (!state.started.count(u->id)) { all = false; break; }
        if (all) for (auto& m : ms) if (!state.started.count(m->id)) { all = false; break; }
        if (all) {
            // ── Transition: WaitForReady → Playing ──
            // Change state BEFORE unlocking to prevent another thread from
            // also entering this branch.
            state.type = InternalRoomState::Type::Playing;
            state.results.clear(); state.aborted.clear(); state.started.clear();
            lk.unlock();

            spdlog::info("room {}: game start", id.to_string());
            Message m; m.type = MessageType::StartPlaying; send_msg(m);
            reset_game_time();
            on_state_change();
        }
    } else if (state.type == InternalRoomState::Type::Playing) {
        auto us = get_users();
        bool all = true;
        for (auto& u : us) if (!state.results.count(u->id) && !state.aborted.count(u->id)) { all = false; break; }
        if (all) {
            // ── Transition: Playing → SelectChart ──
            // Transition state and collect round data while holding the lock.
            { std::unique_lock l3(rounds_mu); std::shared_lock l4(chart_mu);
              RoundData rd; rd.chart = chart ? chart->id : -1;
              for (auto& [uid, rec] : state.results) rd.records.push_back(rec);
              rounds.push_back(rd);
            }
            state.type = InternalRoomState::Type::SelectChart;
            state.results.clear(); state.aborted.clear();
            lk.unlock();

            { Message m; m.type = MessageType::GameEnd; send_msg(m); }

            if (is_cycle()) {
                spdlog::debug("room {}: cycling", id.to_string());
                std::shared_ptr<User> old_h, new_h;
                { std::shared_lock hl(host_mu); old_h = host.lock(); }
                auto us2 = get_users();
                if (!us2.empty()) {
                    size_t idx = 0;
                    for (size_t i = 0; i < us2.size(); i++) if (old_h && us2[i]->id == old_h->id) { idx = (i+1) % us2.size(); break; }
                    new_h = us2[idx];
                    { std::unique_lock hl(host_mu); host = new_h; }
                    Message m; m.type = MessageType::NewHost; m.user = new_h->id; send_msg(m);
                    if (old_h) old_h->try_send(ServerCommand::make_change_host(false));
                    new_h->try_send(ServerCommand::make_change_host(true));
                }
            }
            on_state_change();
        }
    }
}

RoomData Room::into_data() {
    RoomData rd;
    { std::shared_lock lk(host_mu); auto h = host.lock(); rd.host = h ? h->id : -1; }
    for (auto& u : get_users()) rd.users.push_back(u->id);
    rd.lock = is_locked(); rd.cycle = is_cycle();
    { std::shared_lock lk(chart_mu); if (chart) rd.chart = chart->id; }
    { std::shared_lock lk(state_mu); rd.state = state.to_stripped(); }
    { std::shared_lock lk(rounds_mu); rd.rounds = rounds; }
    return rd;
}
