#include "command.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

// ── CompactPos ────────────────────────────────────────────────────────
void CompactPos::read(BinaryReader& r) { x = Float16(r.read_u16()); y = Float16(r.read_u16()); }
void CompactPos::write(BinaryWriter& w) const { w.write_u16(x.bits); w.write_u16(y.bits); }

// ── RoomId ────────────────────────────────────────────────────────────
RoomId::RoomId(const std::string& s) : value(s) {
    if (s.empty() || s.size() > 20) throw std::runtime_error("invalid room id");
    for (char c : s) if (c != '-' && c != '_' && !std::isalnum((unsigned char)c))
        throw std::runtime_error("invalid room id");
}
void RoomId::read(BinaryReader& r) {
    std::string s = r.read_string();
    if (s.size() > 20) throw std::runtime_error("string too long");
    if (s.empty()) throw std::runtime_error("invalid room id");
    for (char c : s) if (c != '-' && c != '_' && !std::isalnum((unsigned char)c))
        throw std::runtime_error("invalid room id");
    value = s;
}
void RoomId::write(BinaryWriter& w) const { w.write_string(value); }

// ── TouchFrame / JudgeEvent ───────────────────────────────────────────
void TouchFrame::read(BinaryReader& r) {
    time = r.read_f32(); uint64_t n = r.read_uleb(); points.resize(n);
    for (auto& p : points) { p.first = r.read_i8(); p.second.read(r); }
}
void TouchFrame::write(BinaryWriter& w) const {
    w.write_f32(time); w.write_uleb(points.size());
    for (auto& p : points) { w.write_i8(p.first); p.second.write(w); }
}
void JudgeEvent::read(BinaryReader& r) {
    time = r.read_f32(); line_id = r.read_u32(); note_id = r.read_u32();
    judgement = static_cast<Judgement>(r.read_u8());
}
void JudgeEvent::write(BinaryWriter& w) const {
    w.write_f32(time); w.write_u32(line_id); w.write_u32(note_id);
    w.write_u8(static_cast<uint8_t>(judgement));
}

// ── UserInfo ──────────────────────────────────────────────────────────
void UserInfo::read(BinaryReader& r) { id = r.read_i32(); name = r.read_string(); monitor = r.read_bool(); }
void UserInfo::write(BinaryWriter& w) const { w.write_i32(id); w.write_string(name); w.write_bool(monitor); }

// ── RoomState ─────────────────────────────────────────────────────────
void RoomState::read(BinaryReader& r) {
    uint8_t t = r.read_u8();
    if (t == 0) { type = RoomStateType::SelectChart; bool h = r.read_bool(); if (h) chart_id = r.read_i32(); else chart_id.reset(); }
    else if (t == 1) type = RoomStateType::WaitingForReady;
    else if (t == 2) type = RoomStateType::Playing;
    else throw std::runtime_error("bad RoomState tag");
}
void RoomState::write(BinaryWriter& w) const {
    switch (type) {
    case RoomStateType::SelectChart: w.write_u8(0); w.write_bool(chart_id.has_value()); if (chart_id) w.write_i32(*chart_id); break;
    case RoomStateType::WaitingForReady: w.write_u8(1); break;
    case RoomStateType::Playing: w.write_u8(2); break;
    }
}

// ── Record ────────────────────────────────────────────────────────────
void Record::read(BinaryReader& r) {
    id=r.read_i32(); player=r.read_i32(); score=r.read_i32(); perfect=r.read_i32(); good=r.read_i32();
    bad=r.read_i32(); miss=r.read_i32(); max_combo=r.read_i32(); accuracy=r.read_f32();
    full_combo=r.read_bool(); std_val=r.read_f32(); std_score=r.read_f32();
}
void Record::write(BinaryWriter& w) const {
    w.write_i32(id); w.write_i32(player); w.write_i32(score); w.write_i32(perfect); w.write_i32(good);
    w.write_i32(bad); w.write_i32(miss); w.write_i32(max_combo); w.write_f32(accuracy);
    w.write_bool(full_combo); w.write_f32(std_val); w.write_f32(std_score);
}
Record Record::from_json(const std::string& s) {
    auto j = nlohmann::json::parse(s); Record r;
    r.id=j.value("id",0); r.player=j.value("player",0); r.score=j.value("score",0);
    r.perfect=j.value("perfect",0); r.good=j.value("good",0); r.bad=j.value("bad",0);
    r.miss=j.value("miss",0); r.max_combo=j.value("max_combo",0);
    r.accuracy=j.value("accuracy",0.0f); r.full_combo=j.value("full_combo",false);
    r.std_val=j.value("std",0.0f); r.std_score=j.value("std_score",0.0f);
    return r;
}

// ── RoundData ─────────────────────────────────────────────────────────
void RoundData::read(BinaryReader& r) {
    chart = r.read_i32(); uint64_t n = r.read_uleb(); records.resize(n);
    for (auto& rec : records) rec.read(r);
}
void RoundData::write(BinaryWriter& w) const {
    w.write_i32(chart); w.write_uleb(records.size());
    for (auto& rec : records) rec.write(w);
}

// ── RoomData / PartialRoomData ────────────────────────────────────────
void RoomData::write(BinaryWriter& w) const {
    w.write_i32(host); w.write_uleb(users.size()); for (auto u : users) w.write_i32(u);
    w.write_bool(lock); w.write_bool(cycle);
    w.write_bool(chart.has_value()); if (chart) w.write_i32(*chart);
    w.write_u8(uint8_t(state)); w.write_uleb(rounds.size()); for (auto& r : rounds) r.write(w);
}
void PartialRoomData::write(BinaryWriter& w) const {
    auto opt_i32 = [&](auto& o) { w.write_bool(o.has_value()); if (o) w.write_i32(*o); };
    auto opt_bool = [&](auto& o) { w.write_bool(o.has_value()); if (o) w.write_bool(*o); };
    opt_i32(host); opt_bool(lock); opt_bool(cycle); opt_i32(chart);
    w.write_bool(state.has_value()); if (state) w.write_u8(uint8_t(*state));
}

// ── ClientRoomState / JoinRoomResponse ────────────────────────────────
void ClientRoomState::write(BinaryWriter& w) const {
    id.write(w); state.write(w);
    w.write_bool(live); w.write_bool(locked); w.write_bool(cycle);
    w.write_bool(is_host); w.write_bool(is_ready);
    w.write_uleb(users.size()); for (auto& [k,v] : users) { w.write_i32(k); v.write(w); }
}
void JoinRoomResponse::write(BinaryWriter& w) const {
    state.write(w); w.write_uleb(users.size()); for (auto& u : users) u.write(w);
    w.write_bool(live);
}

// ── Message ───────────────────────────────────────────────────────────
void Message::write(BinaryWriter& w) const {
    w.write_u8(uint8_t(type));
    switch (type) {
    case MessageType::Chat: w.write_i32(user); w.write_string(content); break;
    case MessageType::CreateRoom: case MessageType::NewHost: case MessageType::GameStart:
    case MessageType::Ready: case MessageType::CancelReady: case MessageType::CancelGame:
    case MessageType::Abort: w.write_i32(user); break;
    case MessageType::JoinRoom: case MessageType::LeaveRoom: w.write_i32(user); w.write_string(name); break;
    case MessageType::SelectChart: w.write_i32(user); w.write_string(name); w.write_i32(chart_id); break;
    case MessageType::StartPlaying: case MessageType::GameEnd: break;
    case MessageType::Played: w.write_i32(user); w.write_i32(score_val); w.write_f32(accuracy); w.write_bool(full_combo); break;
    case MessageType::LockRoom: w.write_bool(lock_val); break;
    case MessageType::CycleRoom: w.write_bool(cycle_val); break;
    }
}

// ── RoomEvent ─────────────────────────────────────────────────────────
void RoomEvent::write(BinaryWriter& w) const {
    w.write_u8(uint8_t(type));
    switch (type) {
    case RoomEventType::CreateRoom: room.write(w); data.write(w); break;
    case RoomEventType::UpdateRoom: room.write(w); partial.write(w); break;
    case RoomEventType::JoinRoom: case RoomEventType::LeaveRoom: room.write(w); w.write_i32(user_id); break;
    case RoomEventType::NewRound: room.write(w); round.write(w); break;
    }
}

// ── ClientCommand ─────────────────────────────────────────────────────
ClientCommand ClientCommand::read_from(BinaryReader& r) {
    ClientCommand c; c.type = ClientCommandType(r.read_u8());
    switch (c.type) {
    case ClientCommandType::Ping: break;
    case ClientCommandType::Authenticate: case ClientCommandType::ConsoleAuthenticate:
    case ClientCommandType::GameMonitorAuthenticate:
        c.token = r.read_string(); if (c.token.size() > 32) throw std::runtime_error("token too long"); break;
    case ClientCommandType::Chat:
        c.message = r.read_string(); if (c.message.size() > 200) throw std::runtime_error("msg too long"); break;
    case ClientCommandType::Touches: { uint64_t n = r.read_uleb(); c.frames.resize(n); for (auto& f : c.frames) f.read(r); break; }
    case ClientCommandType::Judges: { uint64_t n = r.read_uleb(); c.judges.resize(n); for (auto& j : c.judges) j.read(r); break; }
    case ClientCommandType::CreateRoom: c.room_id.read(r); break;
    case ClientCommandType::JoinRoom: c.room_id.read(r); c.monitor = r.read_bool(); break;
    case ClientCommandType::LeaveRoom: break;
    case ClientCommandType::LockRoom: c.lock_val = r.read_bool(); break;
    case ClientCommandType::CycleRoom: c.cycle_val = r.read_bool(); break;
    case ClientCommandType::SelectChart: c.chart_id = r.read_i32(); break;
    case ClientCommandType::RequestStart: case ClientCommandType::Ready:
    case ClientCommandType::CancelReady: case ClientCommandType::Abort: break;
    case ClientCommandType::Played: c.chart_id = r.read_i32(); break;
    case ClientCommandType::RoomMonitorAuthenticate: {
        uint64_t n = r.read_uleb(); c.key.resize(n); for (auto& b : c.key) b = r.read_u8(); break; }
    case ClientCommandType::QueryRoomInfo: break;
    default: throw std::runtime_error("unknown client cmd");
    }
    return c;
}

// ── ServerCommand::write_to ───────────────────────────────────────────
void ServerCommand::write_to(BinaryWriter& w) const {
    w.write_u8(uint8_t(type));
    switch (type) {
    case ServerCommandType::Pong: break;
    case ServerCommandType::Authenticate:
        if (ok) { w.write_bool(true); user_info.write(w);
            w.write_bool(client_room_state.has_value()); if (client_room_state) client_room_state->write(w);
        } else { w.write_bool(false); w.write_string(err_msg); } break;
    case ServerCommandType::Chat: case ServerCommandType::CreateRoom: case ServerCommandType::LeaveRoom:
    case ServerCommandType::LockRoom: case ServerCommandType::CycleRoom: case ServerCommandType::SelectChart:
    case ServerCommandType::RequestStart: case ServerCommandType::Ready: case ServerCommandType::CancelReady:
    case ServerCommandType::Played: case ServerCommandType::Abort:
        write_sresult_unit(w, ok, err_msg); break;
    case ServerCommandType::Touches:
        w.write_i32(player_id); w.write_uleb(frames.size()); for (auto& f : frames) f.write(w); break;
    case ServerCommandType::Judges:
        w.write_i32(player_id); w.write_uleb(judges.size()); for (auto& j : judges) j.write(w); break;
    case ServerCommandType::MessageCmd: message.write(w); break;
    case ServerCommandType::ChangeState: room_state.write(w); break;
    case ServerCommandType::ChangeHost: w.write_bool(host_flag); break;
    case ServerCommandType::JoinRoom:
        if (ok) { w.write_bool(true); join_response.write(w); } else { w.write_bool(false); w.write_string(err_msg); } break;
    case ServerCommandType::OnJoinRoom: user_info.write(w); break;
    case ServerCommandType::RoomResponse:
        if (ok) { w.write_bool(true);
            w.write_uleb(room_map.size()); for (auto& [k,v] : room_map) { w.write_string(k); v.write(w); }
            w.write_uleb(user_room_map.size()); for (auto& [k,v] : user_room_map) { w.write_i32(k); w.write_string(v); }
        } else { w.write_bool(false); w.write_string(err_msg); } break;
    case ServerCommandType::RoomEventCmd: room_event.write(w); break;
    case ServerCommandType::UserVisit: w.write_i32(visit_user_id); break;
    }
}

// ── Factory helpers ───────────────────────────────────────────────────
ServerCommand ServerCommand::make_pong() { ServerCommand c; c.type = ServerCommandType::Pong; return c; }
ServerCommand ServerCommand::make_ok(ServerCommandType t) { ServerCommand c; c.type = t; c.ok = true; return c; }
ServerCommand ServerCommand::make_err(ServerCommandType t, const std::string& m) {
    ServerCommand c; c.type = t; c.ok = false; c.err_msg = m; return c; }
ServerCommand ServerCommand::make_auth_ok(const UserInfo& i, const std::optional<ClientRoomState>& r) {
    ServerCommand c; c.type = ServerCommandType::Authenticate; c.ok = true; c.user_info = i; c.client_room_state = r; return c; }
ServerCommand ServerCommand::make_auth_err(const std::string& m) { return make_err(ServerCommandType::Authenticate, m); }
ServerCommand ServerCommand::make_join_ok(const JoinRoomResponse& r) {
    ServerCommand c; c.type = ServerCommandType::JoinRoom; c.ok = true; c.join_response = r; return c; }
ServerCommand ServerCommand::make_message(const Message& m) {
    ServerCommand c; c.type = ServerCommandType::MessageCmd; c.message = m; return c; }
ServerCommand ServerCommand::make_change_state(const RoomState& s) {
    ServerCommand c; c.type = ServerCommandType::ChangeState; c.room_state = s; return c; }
ServerCommand ServerCommand::make_change_host(bool h) {
    ServerCommand c; c.type = ServerCommandType::ChangeHost; c.host_flag = h; return c; }
ServerCommand ServerCommand::make_on_join(const UserInfo& i) {
    ServerCommand c; c.type = ServerCommandType::OnJoinRoom; c.user_info = i; return c; }
ServerCommand ServerCommand::make_touches(int32_t p, const std::vector<TouchFrame>& f) {
    ServerCommand c; c.type = ServerCommandType::Touches; c.player_id = p; c.frames = f; return c; }
ServerCommand ServerCommand::make_judges(int32_t p, const std::vector<JudgeEvent>& j) {
    ServerCommand c; c.type = ServerCommandType::Judges; c.player_id = p; c.judges = j; return c; }
ServerCommand ServerCommand::make_room_event(const RoomEvent& e) {
    ServerCommand c; c.type = ServerCommandType::RoomEventCmd; c.room_event = e; return c; }
ServerCommand ServerCommand::make_user_visit(int32_t id) {
    ServerCommand c; c.type = ServerCommandType::UserVisit; c.visit_user_id = id; return c; }
ServerCommand ServerCommand::make_room_response(const std::map<std::string,RoomData>& rm, const std::map<int32_t,std::string>& um) {
    ServerCommand c; c.type = ServerCommandType::RoomResponse; c.ok = true; c.room_map = rm; c.user_room_map = um; return c; }
