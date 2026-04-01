#include "binary.hpp"
#ifdef _WIN32
#include <rpc.h>
#ifdef _MSC_VER
#pragma comment(lib, "rpcrt4.lib")
#endif
#else
#include <uuid/uuid.h>
#endif
#include <cmath>

// ── Float16 ───────────────────────────────────────────────────────────
Float16 Float16::from_f32(float v) {
    uint32_t f; std::memcpy(&f, &v, 4);
    uint32_t sign = (f >> 16) & 0x8000;
    int32_t exp = ((f >> 23) & 0xFF) - 127 + 15;
    uint32_t man = (f >> 13) & 0x03FF;
    if (exp <= 0) return Float16(uint16_t(sign));
    if (exp >= 31) return Float16(uint16_t(sign | 0x7C00));
    return Float16(uint16_t(sign | (exp << 10) | man));
}

float Float16::to_f32() const {
    uint32_t sign = (bits & 0x8000) << 16;
    uint32_t exp = (bits >> 10) & 0x1F;
    uint32_t man = bits & 0x03FF;
    if (exp == 0) {
        if (man == 0) { float r; uint32_t v = sign; std::memcpy(&r, &v, 4); return r; }
        while (!(man & 0x0400)) { man <<= 1; exp--; }
        exp++; man &= ~0x0400;
    } else if (exp == 31) {
        uint32_t v = sign | 0x7F800000 | (man << 13);
        float r; std::memcpy(&r, &v, 4); return r;
    }
    exp += 127 - 15;
    uint32_t v = sign | (exp << 23) | (man << 13);
    float r; std::memcpy(&r, &v, 4); return r;
}

// ── Uuid ──────────────────────────────────────────────────────────────
Uuid Uuid::generate() {
#ifdef _WIN32
    ::UUID raw;
    UuidCreate(&raw);
    uint64_t h = 0, l = 0;
    auto* b = reinterpret_cast<const uint8_t*>(&raw);
    for (int i = 0; i < 8; i++) { h = (h << 8) | b[i]; l = (l << 8) | b[i + 8]; }
    return {h, l};
#else
    uuid_t raw; uuid_generate(raw);
    uint64_t h = 0, l = 0;
    for (int i = 0; i < 8; i++) { h = (h << 8) | raw[i]; l = (l << 8) | raw[i + 8]; }
    return {h, l};
#endif
}
std::string Uuid::to_string() const {
    std::ostringstream o; o << std::hex << std::setfill('0');
    o << std::setw(8) << uint32_t(high >> 32) << '-'
      << std::setw(4) << uint16_t(high >> 16) << '-'
      << std::setw(4) << uint16_t(high) << '-'
      << std::setw(4) << uint16_t(low >> 48) << '-'
      << std::setw(12) << (low & 0xFFFFFFFFFFFF);
    return o.str();
}
size_t UuidHash::operator()(const Uuid& u) const {
    return std::hash<uint64_t>()(u.high) ^ (std::hash<uint64_t>()(u.low) << 1);
}

// ── BinaryReader ──────────────────────────────────────────────────────
uint8_t BinaryReader::read_u8() {
    if (pos_ >= len_) throw std::runtime_error("unexpected EOF");
    return d_[pos_++];
}
const uint8_t* BinaryReader::take(size_t n) {
    if (pos_ + n > len_) throw std::runtime_error("unexpected EOF");
    auto p = d_ + pos_; pos_ += n; return p;
}
uint16_t BinaryReader::read_u16() { auto p = take(2); return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
uint32_t BinaryReader::read_u32() { auto p = take(4); uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | p[i]; return v; }
uint64_t BinaryReader::read_u64() { auto p = take(8); uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
float BinaryReader::read_f32() { uint32_t b = read_u32(); float v; std::memcpy(&v, &b, 4); return v; }
double BinaryReader::read_f64() { uint64_t b = read_u64(); double v; std::memcpy(&v, &b, 8); return v; }
std::string BinaryReader::read_string() {
    uint64_t len = read_uleb(); auto p = take(size_t(len));
    return std::string(reinterpret_cast<const char*>(p), size_t(len));
}
uint64_t BinaryReader::read_uleb() {
    uint64_t r = 0; uint32_t s = 0;
    for (;;) { uint8_t b = read_u8(); r |= uint64_t(b & 0x7F) << s; if (!(b & 0x80)) break; s += 7; if (s > 63) throw std::runtime_error("ULEB overflow"); }
    return r;
}
Uuid BinaryReader::read_uuid() { uint64_t lo = read_u64(), hi = read_u64(); return {hi, lo}; }

// ── BinaryWriter ──────────────────────────────────────────────────────
void BinaryWriter::write_u16(uint16_t v) { buf_.push_back(v & 0xFF); buf_.push_back((v >> 8) & 0xFF); }
void BinaryWriter::write_u32(uint32_t v) { for (int i = 0; i < 4; i++) buf_.push_back((v >> (i * 8)) & 0xFF); }
void BinaryWriter::write_u64(uint64_t v) { for (int i = 0; i < 8; i++) buf_.push_back((v >> (i * 8)) & 0xFF); }
void BinaryWriter::write_f32(float v) { uint32_t b; std::memcpy(&b, &v, 4); write_u32(b); }
void BinaryWriter::write_f64(double v) { uint64_t b; std::memcpy(&b, &v, 8); write_u64(b); }
void BinaryWriter::write_string(const std::string& s) { write_uleb(s.size()); buf_.insert(buf_.end(), s.begin(), s.end()); }
void BinaryWriter::write_uleb(uint64_t v) { do { uint8_t b = v & 0x7F; v >>= 7; if (v) b |= 0x80; write_u8(b); } while (v); }
void BinaryWriter::write_uuid(const Uuid& u) { write_u64(u.low); write_u64(u.high); }
