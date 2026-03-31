#pragma once
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <iomanip>

// ── Half-float (f16) ──────────────────────────────────────────────────
struct Float16 {
    uint16_t bits = 0;
    Float16() = default;
    explicit Float16(uint16_t raw) : bits(raw) {}
    static Float16 from_f32(float v);
    float to_f32() const;
};

// ── UUID (128-bit) ────────────────────────────────────────────────────
struct Uuid {
    uint64_t high = 0, low = 0;
    Uuid() = default;
    Uuid(uint64_t h, uint64_t l) : high(h), low(l) {}
    static Uuid generate();
    std::string to_string() const;
    bool operator==(const Uuid& o) const { return high == o.high && low == o.low; }
    bool operator<(const Uuid& o) const { return high < o.high || (high == o.high && low < o.low); }
};
struct UuidHash { size_t operator()(const Uuid& u) const; };

// ── BinaryReader ──────────────────────────────────────────────────────
class BinaryReader {
public:
    BinaryReader(const uint8_t* data, size_t len) : d_(data), len_(len) {}
    explicit BinaryReader(const std::vector<uint8_t>& v) : d_(v.data()), len_(v.size()) {}
    uint8_t  read_u8();
    int8_t   read_i8()   { return static_cast<int8_t>(read_u8()); }
    uint16_t read_u16();
    uint32_t read_u32();
    uint64_t read_u64();
    int32_t  read_i32()  { return static_cast<int32_t>(read_u32()); }
    int64_t  read_i64()  { return static_cast<int64_t>(read_u64()); }
    float    read_f32();
    double   read_f64();
    bool     read_bool() { return read_u8() == 1; }
    std::string read_string();
    uint64_t read_uleb();
    Uuid     read_uuid();
    const uint8_t* take(size_t n);
    size_t remaining() const { return len_ - pos_; }
private:
    const uint8_t* d_; size_t len_ = 0; size_t pos_ = 0;
};

// ── BinaryWriter ──────────────────────────────────────────────────────
class BinaryWriter {
public:
    explicit BinaryWriter(std::vector<uint8_t>& buf) : buf_(buf) {}
    void write_u8(uint8_t v)       { buf_.push_back(v); }
    void write_i8(int8_t v)        { buf_.push_back(static_cast<uint8_t>(v)); }
    void write_u16(uint16_t v);
    void write_u32(uint32_t v);
    void write_u64(uint64_t v);
    void write_i32(int32_t v)      { write_u32(static_cast<uint32_t>(v)); }
    void write_i64(int64_t v)      { write_u64(static_cast<uint64_t>(v)); }
    void write_f32(float v);
    void write_f64(double v);
    void write_bool(bool v)        { write_u8(v ? 1 : 0); }
    void write_string(const std::string& s);
    void write_uleb(uint64_t v);
    void write_uuid(const Uuid& u);
    void write_bytes(const uint8_t* p, size_t n) { buf_.insert(buf_.end(), p, p + n); }
    std::vector<uint8_t>& buffer() { return buf_; }
private:
    std::vector<uint8_t>& buf_;
};

// ── Helpers for writing Result<T,String> (SResult) ────────────────────
inline void write_sresult_unit(BinaryWriter& w, bool ok, const std::string& err = "") {
    w.write_bool(ok);
    if (!ok) w.write_string(err);
}
