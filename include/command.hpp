#pragma once
#include "binary.hpp"
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// ── CompactPos ────────────────────────────────────────────────────────
struct CompactPos {
    Float16 x, y;
    CompactPos() = default;
    CompactPos(float fx, float fy) : x(Float16::from_f32(fx)), y(Float16::from_f32(fy)) {}
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
};

// ── RoomId ────────────────────────────────────────────────────────────
struct RoomId {
    std::string value;
    RoomId() = default;
    explicit RoomId(const std::string& s);       // validates
    bool operator==(const RoomId& o) const { return value == o.value; }
    bool operator<(const RoomId& o) const  { return value < o.value; }
    std::string to_string() const { return value; }
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
};
struct RoomIdHash { size_t operator()(const RoomId& r) const { return std::hash<std::string>()(r.value); } };

// ── Judgement ─────────────────────────────────────────────────────────
enum class Judgement : uint8_t { Perfect=0, Good=1, Bad=2, Miss=3, HoldPerfect=4, HoldGood=5 };

// ── TouchFrame / JudgeEvent ───────────────────────────────────────────
struct TouchFrame {
    float time = 0;
    std::vector<std::pair<int8_t, CompactPos>> points;
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
};
struct JudgeEvent {
    float time = 0; uint32_t line_id = 0, note_id = 0; Judgement judgement{};
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
};

// ── UserInfo ──────────────────────────────────────────────────────────
struct UserInfo {
    int32_t id = 0; std::string name; bool monitor = false;
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
};

// ── RoomState ─────────────────────────────────────────────────────────
enum class RoomStateType : uint8_t { SelectChart=0, WaitingForReady=1, Playing=2 };
struct RoomState {
    RoomStateType type = RoomStateType::SelectChart;
    std::optional<int32_t> chart_id;
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
};

// ── StrippedRoomState ─────────────────────────────────────────────────
enum class StrippedRoomState : uint8_t { SelectingChart=0, WaitingForReady=1, Playing=2 };

// ── Record ────────────────────────────────────────────────────────────
struct Record {
    int32_t id=0, player=0, score=0, perfect=0, good=0, bad=0, miss=0, max_combo=0;
    float accuracy=0; bool full_combo=false; float std_val=0, std_score=0;
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
    static Record from_json(const std::string& json_str);
};

// ── RoundData ─────────────────────────────────────────────────────────
struct RoundData {
    int32_t chart = -1;
    std::vector<Record> records;
    void read(BinaryReader& r);
    void write(BinaryWriter& w) const;
};

// ── RoomData / PartialRoomData ────────────────────────────────────────
struct RoomData {
    int32_t host = -1; std::vector<int32_t> users;
    bool lock = false, cycle = false;
    std::optional<int32_t> chart;
    StrippedRoomState state = StrippedRoomState::SelectingChart;
    std::vector<RoundData> rounds;
    void write(BinaryWriter& w) const;
};
struct PartialRoomData {
    std::optional<int32_t> host;
    std::optional<bool> lock, cycle;
    std::optional<int32_t> chart;
    std::optional<StrippedRoomState> state;
    void write(BinaryWriter& w) const;
};

// ── ClientRoomState ───────────────────────────────────────────────────
struct ClientRoomState {
    RoomId id; RoomState state;
    bool live=false, locked=false, cycle=false, is_host=false, is_ready=false;
    std::map<int32_t, UserInfo> users;
    void write(BinaryWriter& w) const;
};

// ── JoinRoomResponse ──────────────────────────────────────────────────
struct JoinRoomResponse {
    RoomState state; std::vector<UserInfo> users; bool live = false;
    void write(BinaryWriter& w) const;
};

// ── Message ───────────────────────────────────────────────────────────
enum class MessageType : uint8_t {
    Chat=0, CreateRoom=1, JoinRoom=2, LeaveRoom=3, NewHost=4,
    SelectChart=5, GameStart=6, Ready=7, CancelReady=8, CancelGame=9,
    StartPlaying=10, Played=11, GameEnd=12, Abort=13, LockRoom=14, CycleRoom=15,
};
struct Message {
    MessageType type{};
    int32_t user = 0;
    std::string content;   // Chat
    std::string name;      // JoinRoom/LeaveRoom/SelectChart
    int32_t chart_id = 0;  // SelectChart/Played
    int32_t score_val = 0; // Played
    float accuracy = 0;    // Played
    bool full_combo = false;
    bool lock_val = false;  // LockRoom
    bool cycle_val = false; // CycleRoom
    void write(BinaryWriter& w) const;
};

// ── RoomEvent ─────────────────────────────────────────────────────────
enum class RoomEventType : uint8_t { CreateRoom=0, UpdateRoom=1, JoinRoom=2, LeaveRoom=3, NewRound=4 };
struct RoomEvent {
    RoomEventType type{};
    RoomId room;
    RoomData data;
    PartialRoomData partial;
    int32_t user_id = 0;
    RoundData round;
    void write(BinaryWriter& w) const;
};

// ── ClientCommand ─────────────────────────────────────────────────────
enum class ClientCommandType : uint8_t {
    Ping=0, Authenticate=1, Chat=2, Touches=3, Judges=4,
    CreateRoom=5, JoinRoom=6, LeaveRoom=7, LockRoom=8, CycleRoom=9,
    SelectChart=10, RequestStart=11, Ready=12, CancelReady=13, Played=14, Abort=15,
    ConsoleAuthenticate=16, RoomMonitorAuthenticate=17, QueryRoomInfo=18, GameMonitorAuthenticate=19,
};
struct ClientCommand {
    ClientCommandType type{};
    std::string token;
    std::string message;
    std::vector<TouchFrame> frames;
    std::vector<JudgeEvent> judges;
    RoomId room_id;
    bool monitor = false, lock_val = false, cycle_val = false;
    int32_t chart_id = 0;
    std::vector<uint8_t> key;
    static ClientCommand read_from(BinaryReader& r);
};

// ── ServerCommand ─────────────────────────────────────────────────────
enum class ServerCommandType : uint8_t {
    Pong=0, Authenticate=1, Chat=2, Touches=3, Judges=4,
    MessageCmd=5, ChangeState=6, ChangeHost=7,
    CreateRoom=8, JoinRoom=9, OnJoinRoom=10, LeaveRoom=11,
    LockRoom=12, CycleRoom=13, SelectChart=14, RequestStart=15,
    Ready=16, CancelReady=17, Played=18, Abort=19,
    RoomResponse=20, RoomEventCmd=21, UserVisit=22,
};
struct ServerCommand {
    ServerCommandType type{};
    bool ok = true;
    std::string err_msg;
    // Payload fields (union-like, used by type)
    UserInfo user_info;
    std::optional<ClientRoomState> client_room_state;
    JoinRoomResponse join_response;
    bool host_flag = false;
    RoomState room_state;
    int32_t player_id = 0;
    std::vector<TouchFrame> frames;
    std::vector<JudgeEvent> judges;
    Message message;
    RoomEvent room_event;
    int32_t visit_user_id = 0;
    std::map<std::string, RoomData> room_map;
    std::map<int32_t, std::string> user_room_map;

    void write_to(BinaryWriter& w) const;

    // Factory helpers
    static ServerCommand make_pong();
    static ServerCommand make_ok(ServerCommandType t);
    static ServerCommand make_err(ServerCommandType t, const std::string& msg);
    static ServerCommand make_auth_ok(const UserInfo& i, const std::optional<ClientRoomState>& r);
    static ServerCommand make_auth_err(const std::string& m);
    static ServerCommand make_join_ok(const JoinRoomResponse& r);
    static ServerCommand make_message(const Message& m);
    static ServerCommand make_change_state(const RoomState& s);
    static ServerCommand make_change_host(bool h);
    static ServerCommand make_on_join(const UserInfo& i);
    static ServerCommand make_touches(int32_t p, const std::vector<TouchFrame>& f);
    static ServerCommand make_judges(int32_t p, const std::vector<JudgeEvent>& j);
    static ServerCommand make_room_event(const RoomEvent& e);
    static ServerCommand make_user_visit(int32_t id);
    static ServerCommand make_room_response(const std::map<std::string,RoomData>& rm,
                                            const std::map<int32_t,std::string>& um);
};
