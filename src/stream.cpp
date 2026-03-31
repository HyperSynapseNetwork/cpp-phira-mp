#include "stream.hpp"
#include <spdlog/spdlog.h>
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <cstdlib>

// ── TcpBinaryStream ───────────────────────────────────────────────────
TcpBinaryStream::TcpBinaryStream(tcp::socket socket, asio::io_context& ioc)
    : socket_(std::move(socket)), ioc_(ioc), strand_(ioc) {
    error_code ec; socket_.set_option(tcp::no_delay(true), ec);
}
TcpBinaryStream::~TcpBinaryStream() { error_code ec; socket_.close(ec); }

void TcpBinaryStream::start_server_side(RecvHandler on_recv, ErrorHandler on_error) {
    on_recv_ = std::move(on_recv); on_error_ = std::move(on_error); read_version();
}

void TcpBinaryStream::read_version() {
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(byte_buf_), [self](error_code ec, size_t) {
        if (ec) { if (self->on_error_) self->on_error_("read version: " + ec.message()); return; }
        self->version_ = self->byte_buf_[0]; self->read_varint();
    });
}

// ──────────────────────────────────────────────────────────────────────
// FIX: replaced stack-local VR struct with a member function.
// The old code created a VR{} on the stack, called operator()() which
// started an async_read capturing `this` (pointer into the stack frame).
// When read_varint() returned, the VR was destroyed, and the async
// callback later dereferenced a dangling `this` → segfault.
// ──────────────────────────────────────────────────────────────────────
void TcpBinaryStream::read_varint() {
    varint_value_ = 0; varint_shift_ = 0;
    do_read_varint_byte();
}

void TcpBinaryStream::do_read_varint_byte() {
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(byte_buf_), [self](error_code ec, size_t) {
        if (ec) { if (self->on_error_) self->on_error_("read len: " + ec.message()); return; }
        uint8_t b = self->byte_buf_[0];
        self->varint_value_ |= uint32_t(b & 0x7F) << self->varint_shift_;
        self->varint_shift_ += 7;
        if (!(b & 0x80)) {
            if (self->varint_value_ > 2*1024*1024) {
                if (self->on_error_) self->on_error_("too large");
                return;
            }
            self->read_body(self->varint_value_);
        } else if (self->varint_shift_ > 32) {
            if (self->on_error_) self->on_error_("bad varint");
        } else {
            self->do_read_varint_byte();
        }
    });
}

void TcpBinaryStream::read_body(uint32_t len) {
    recv_buf_.resize(len);
    if (!len) { read_varint(); return; }
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(recv_buf_), [self](error_code ec, size_t) {
        if (ec) { if (self->on_error_) self->on_error_("read body: " + ec.message()); return; }
        try { BinaryReader r(self->recv_buf_); auto cmd = ClientCommand::read_from(r); if (self->on_recv_) self->on_recv_(std::move(cmd)); }
        catch (const std::exception& e) { spdlog::warn("invalid packet: {}", e.what()); }
        self->read_varint();
    });
}

// ──────────────────────────────────────────────────────────────────────
// FIX: send() previously called do_write() while holding send_mutex_.
// do_write() also locks send_mutex_ → instant deadlock on the first
// message ever sent.  The auth response was never delivered, so the
// Phira client saw a timeout.
//
// Solution: release the lock before kicking off do_write(), and post
// do_write() through the strand so that async_write calls are always
// serialised.
// ──────────────────────────────────────────────────────────────────────
void TcpBinaryStream::send(const ServerCommand& cmd) {
    std::vector<uint8_t> payload; BinaryWriter w(payload); cmd.write_to(w);
    std::vector<uint8_t> pkt;
    uint32_t len = uint32_t(payload.size());
    do { uint8_t b = len & 0x7F; len >>= 7; if (len) b |= 0x80; pkt.push_back(b); } while (len);
    pkt.insert(pkt.end(), payload.begin(), payload.end());

    bool start_write = false;
    {
        std::lock_guard<std::mutex> lk(send_mutex_);
        send_queue_.push(std::move(pkt));
        if (!sending_) { sending_ = true; start_write = true; }
    }
    // Kick off writing *outside* the lock, via the strand
    if (start_write) {
        asio::post(strand_, [self = shared_from_this()]() { self->do_write(); });
    }
}

void TcpBinaryStream::do_write() {
    auto self = shared_from_this();
    std::vector<uint8_t> data;
    { std::lock_guard<std::mutex> lk(send_mutex_);
      if (send_queue_.empty()) { sending_ = false; return; }
      data = std::move(send_queue_.front()); send_queue_.pop(); }
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(data));
    asio::async_write(socket_, asio::buffer(*buf),
        asio::bind_executor(strand_, [self, buf](error_code ec, size_t) {
            if (ec) { spdlog::error("write error: {}", ec.message()); return; }
            self->do_write();
        }));
}

// ──────────────────────────────────────────────────────────────────────
// generate_secret_key — must produce byte-identical output to the Rust
// phira_mp_common::generate_secret_key.
//
// Rust uses:
//   Argon2::default()  → argon2id, version 0x13, t_cost=2, m_cost=19456, p_cost=1, output=32
//   SaltString::encode_b64(b"some$random#salt")  → raw salt bytes
//   hkdf::Hkdf::<Sha256>::new(None, ikm)  → full extract+expand (salt = empty)
//   h.expand(info, &mut okm)
//
// The old C++ code had t=3, m=65536 and used HKDF expand-only, which
// produced a completely different key → "secret key mismatch".
// ──────────────────────────────────────────────────────────────────────
std::vector<uint8_t> generate_secret_key(const std::string& info, size_t len) {
    const char* env = std::getenv("HSN_SECRET_KEY");
    std::string secret = env ? env : "some_random_secret_key_for_debugging";
    if (!env) spdlog::warn("HSN_SECRET_KEY not set, using default");

    const uint8_t salt[] = "some$random#salt";
    std::vector<uint8_t> hash(32);
    // Match Rust argon2 0.5.x defaults: t_cost=2, m_cost=19456 KiB, parallelism=1
    int rc = argon2id_hash_raw(2, 19456, 1, secret.data(), secret.size(),
                               salt, sizeof(salt)-1, hash.data(), hash.size());
    if (rc != ARGON2_OK)
        throw std::runtime_error(std::string("argon2 failed: ") + argon2_error_message(rc));

    // Full HKDF (extract + expand) matching Rust hkdf::Hkdf::new(None, ikm)
    // When salt is None in the Rust crate, it uses an all-zeros salt of
    // hash-length (32 bytes for SHA-256).
    std::vector<uint8_t> okm(len);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) throw std::runtime_error("HKDF init fail");
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    // Use EXTRACT_AND_EXPAND mode (the default, matching Rust's full HKDF)
    EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);
    // salt = NULL → OpenSSL uses all-zeros salt (matches Rust Hkdf::new(None, ..))
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, nullptr, 0);
    EVP_PKEY_CTX_set1_hkdf_key(ctx, hash.data(), hash.size());
    EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char*)info.data(), info.size());
    size_t outlen = len;
    if (EVP_PKEY_derive(ctx, okm.data(), &outlen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("HKDF derive fail");
    }
    EVP_PKEY_CTX_free(ctx);
    return okm;
}
