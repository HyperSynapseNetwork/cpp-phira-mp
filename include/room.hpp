#pragma once
#include "command.hpp"
#include "l10n.hpp"
#include <atomic>
#include <map>
#include <memory>
#include <set>
#include <shared_mutex>
#include <vector>

class User;
constexpr size_t ROOM_MAX_USERS = 100;

struct InternalRoomState {
    enum class Type { SelectChart, WaitForReady, Playing };
    Type type = Type::SelectChart;
    std::set<int32_t> started;              // WaitForReady
    std::map<int32_t, Record> results;      // Playing
    std::set<int32_t> aborted;              // Playing

    RoomState to_client(std::optional<int32_t> chart) const;
    StrippedRoomState to_stripped() const;
};

struct ChartInfo { int32_t id = 0; std::string name; };

class Room : public std::enable_shared_from_this<Room> {
public:
    Room(const RoomId& id, std::weak_ptr<User> host);

    bool is_live()   const { return live_.load(std::memory_order_seq_cst); }
    bool is_locked() const { return locked_.load(std::memory_order_seq_cst); }
    bool is_cycle()  const { return cycle_.load(std::memory_order_seq_cst); }
    void set_live(bool v)   { live_.store(v, std::memory_order_seq_cst); }
    void set_locked(bool v) { locked_.store(v, std::memory_order_seq_cst); }
    void set_cycle(bool v)  { cycle_.store(v, std::memory_order_seq_cst); }

    RoomState client_room_state();
    ClientRoomState client_state(const User& u);
    bool add_user(std::weak_ptr<User> u, bool mon);
    std::vector<std::shared_ptr<User>> get_users();
    std::vector<std::shared_ptr<User>> get_monitors();
    void check_host_throw(const User& u);
    void send_msg(const Message& m);
    void broadcast(const ServerCommand& c);
    void broadcast_monitors(const ServerCommand& c);
    void send_as(const User& u, const std::string& content);
    bool on_user_leave(const User& u);   // returns true if room should be dropped
    void on_state_change();
    void reset_game_time();
    void check_all_ready();
    RoomData into_data();

    RoomId id;
    mutable std::shared_mutex host_mu, state_mu, chart_mu, rounds_mu;
    std::weak_ptr<User> host;
    InternalRoomState state;
    std::optional<ChartInfo> chart;
    std::vector<RoundData> rounds;

private:
    std::atomic<bool> live_{false}, locked_{false}, cycle_{false};
    mutable std::shared_mutex users_mu_, monitors_mu_;
    std::vector<std::weak_ptr<User>> users_, monitors_;
};
