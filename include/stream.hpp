#pragma once
#include "command.hpp"
#include <boost/asio.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using error_code = boost::system::error_code;

constexpr auto HEARTBEAT_DISCONNECT_TIMEOUT = std::chrono::seconds(10);

class TcpBinaryStream : public std::enable_shared_from_this<TcpBinaryStream> {
public:
    using RecvHandler = std::function<void(ClientCommand)>;
    using ErrorHandler = std::function<void(const std::string&)>;

    TcpBinaryStream(tcp::socket socket, asio::io_context& ioc);
    ~TcpBinaryStream();
    void start_server_side(RecvHandler on_recv, ErrorHandler on_error);
    void send(const ServerCommand& cmd);
    uint8_t version() const { return version_; }

private:
    void read_version();
    void read_varint();
    void do_read_varint_byte();   // ← NEW: replaces the stack-local VR struct
    void read_body(uint32_t len);
    void do_write();

    tcp::socket socket_;
    asio::io_context& ioc_;
    asio::io_context::strand strand_;
    uint8_t version_ = 0;
    RecvHandler on_recv_;
    ErrorHandler on_error_;
    std::mutex send_mutex_;
    std::queue<std::vector<uint8_t>> send_queue_;
    bool sending_ = false;
    std::vector<uint8_t> recv_buf_;
    std::array<uint8_t, 1> byte_buf_{};
    uint32_t varint_value_ = 0, varint_shift_ = 0;
};

std::vector<uint8_t> generate_secret_key(const std::string& info, size_t len);
