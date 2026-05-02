// ─────────────────────────────────────────────────────────────────────────
// http_client.cpp — 实现 handle 池 + DNS/SSL session 共享 + 谱面缓存
// ─────────────────────────────────────────────────────────────────────────
#include "http_client.hpp"

#include <curl/curl.h>
#include <spdlog/spdlog.h>
#include <cstdlib>
#include <filesystem>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────
// CA 路径解析（call_once 保证只计算一次且线程安全）
// ─────────────────────────────────────────────────────────────────────────
const std::string& get_ca_path() {
    static std::string ca_path;
    static std::once_flag once;
    std::call_once(once, []() {
        if (auto e = std::getenv("CURL_CA_BUNDLE")) {
            if (fs::exists(e)) { ca_path = e; spdlog::info("CA cert from env: {}", ca_path); return; }
        }
        if (auto e = std::getenv("SSL_CERT_FILE")) {
            if (fs::exists(e)) { ca_path = e; spdlog::info("CA cert from env: {}", ca_path); return; }
        }

        std::string exe_dir;
#ifdef _WIN32
        wchar_t buf[MAX_PATH];
        if (GetModuleFileNameW(nullptr, buf, MAX_PATH))
            exe_dir = fs::path(buf).parent_path().string();
#else
        try { exe_dir = fs::read_symlink("/proc/self/exe").parent_path().string(); }
        catch (...) {}
#endif
        if (!exe_dir.empty()) {
            auto p = exe_dir + "/cacert.pem";
            if (fs::exists(p)) { ca_path = p; spdlog::info("CA cert found: {}", ca_path); return; }
        }

        if (fs::exists("cacert.pem")) {
            ca_path = "cacert.pem";
            spdlog::info("CA cert found: {}", ca_path);
            return;
        }

        for (auto loc : {"/etc/ssl/certs/ca-certificates.crt",
                         "/etc/pki/tls/certs/ca-bundle.crt",
                         "/etc/ssl/cert.pem",
                         "/usr/share/ca-certificates/cacert.pem"}) {
            if (fs::exists(loc)) {
                ca_path = loc;
                spdlog::info("CA cert found: {}", ca_path);
                return;
            }
        }

        spdlog::warn("No CA cert found; HTTPS verification may fail. "
                     "Place cacert.pem next to the executable.");
    });
    return ca_path;
}

// ─────────────────────────────────────────────────────────────────────────
// HttpClient
// ─────────────────────────────────────────────────────────────────────────
HttpClient& HttpClient::instance() {
    static HttpClient inst;
    return inst;
}

HttpClient::HttpClient() {
    init_share();
}

HttpClient::~HttpClient() {
    shutdown();
}

// CURLSH 锁/解锁回调
// 注：CURLSHOPT_LOCKFUNC 的回调对每种 curl_lock_data 是串行调用 lock/unlock 的，
// 所以用普通 std::mutex 即可（CURL 文档明确允许）。
namespace {
std::mutex g_dns_mu, g_ssl_mu, g_conn_mu;
void share_lock_simple(CURL*, curl_lock_data data, curl_lock_access, void*) {
    switch (data) {
        case CURL_LOCK_DATA_DNS:         g_dns_mu.lock(); break;
        case CURL_LOCK_DATA_SSL_SESSION: g_ssl_mu.lock(); break;
        case CURL_LOCK_DATA_CONNECT:     g_conn_mu.lock(); break;
        default: break;
    }
}
void share_unlock_simple(CURL*, curl_lock_data data, void*) {
    switch (data) {
        case CURL_LOCK_DATA_DNS:         g_dns_mu.unlock(); break;
        case CURL_LOCK_DATA_SSL_SESSION: g_ssl_mu.unlock(); break;
        case CURL_LOCK_DATA_CONNECT:     g_conn_mu.unlock(); break;
        default: break;
    }
}
} // namespace

void HttpClient::init_share() {
    share_ = curl_share_init();
    if (!share_) {
        spdlog::error("curl_share_init failed; falling back to non-shared mode");
        return;
    }
    curl_share_setopt(share_, CURLSHOPT_LOCKFUNC, share_lock_simple);
    curl_share_setopt(share_, CURLSHOPT_UNLOCKFUNC, share_unlock_simple);
    // 共享 DNS 解析缓存——避免每次都做 DNS 查询
    curl_share_setopt(share_, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    // 共享 SSL session——避免每次都做完整 TLS 握手
    curl_share_setopt(share_, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    // 共享连接缓存（CURL 7.57+）——多个 handle 可借用彼此的 keep-alive 连接
    curl_share_setopt(share_, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
}

void HttpClient::shutdown() {
    if (shutdown_.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lk(pool_mu_);
        for (auto* h : pool_) curl_easy_cleanup(h);
        pool_.clear();
    }
    if (share_) {
        curl_share_cleanup(share_);
        share_ = nullptr;
    }
}

// 内部回调
static size_t curl_write_cb(void* p, size_t sz, size_t nm, std::string* o) {
    o->append(static_cast<char*>(p), sz * nm);
    return sz * nm;
}

CURL* HttpClient::acquire() {
    {
        std::lock_guard<std::mutex> lk(pool_mu_);
        if (!pool_.empty()) {
            CURL* h = pool_.back();
            pool_.pop_back();
            curl_easy_reset(h);   // 重置选项，但保留连接缓存与 share 关联
            return h;
        }
    }
    CURL* h = curl_easy_init();
    if (!h) throw std::runtime_error("curl_easy_init failed");
    return h;
}

void HttpClient::release(CURL* h) {
    if (!h) return;
    if (shutdown_.load()) { curl_easy_cleanup(h); return; }
    std::lock_guard<std::mutex> lk(pool_mu_);
    if (pool_.size() >= kMaxPooled) {
        curl_easy_cleanup(h);
    } else {
        pool_.push_back(h);
    }
}

// ── 关键：每次请求复用 handle、复用 DNS、复用 SSL session、复用 TCP 连接 ──
std::string HttpClient::get(const std::string& url, const std::string& auth) {
    CURL* c = acquire();
    std::string resp;
    struct curl_slist* hdrs = nullptr;

    try {
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);

        // 超时：连接 8s，整体 12s——对网络抖动更宽容
        // （客户端侧典型的"HTTP Timeout"是连接阶段的失败；放宽 connect 超时，
        //   并配合下面的 IPv4 优先 + TFO 与共享 DNS 来减少首次连接成本）
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 8000L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 12000L);

        // 性能选项
        curl_easy_setopt(c, CURLOPT_TCP_NODELAY,  1L);
        curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(c, CURLOPT_TCP_KEEPIDLE,  30L);
        curl_easy_setopt(c, CURLOPT_TCP_KEEPINTVL, 10L);
        // CURL 7.49+：启用 TCP Fast Open（TFO），减少一次 RTT
        curl_easy_setopt(c, CURLOPT_TCP_FASTOPEN, 1L);
        // 优先 IPv4——许多家宽 IPv6 路径慢/丢包，导致首次连接超时
        curl_easy_setopt(c, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);

        // 关键：明确允许复用、不强制关闭
        curl_easy_setopt(c, CURLOPT_FORBID_REUSE, 0L);
        curl_easy_setopt(c, CURLOPT_FRESH_CONNECT, 0L);
        // 维持长连接：让本 handle 之内的连接缓存留够
        curl_easy_setopt(c, CURLOPT_MAXCONNECTS, 8L);

        // 启用所有压缩——服务器 / 路由器中间件常有问题，但对 phira API 是稳健的
        curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");

        // 静默 signals（多线程中必须，避免 CURL 装 SIGALRM 处理器）
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);

        // CA 证书
        const auto& ca = get_ca_path();
        if (!ca.empty()) curl_easy_setopt(c, CURLOPT_CAINFO, ca.c_str());

        // 鉴权头
        if (!auth.empty()) {
            hdrs = curl_slist_append(hdrs, ("Authorization: " + auth).c_str());
            // 启用连接重用提示
            hdrs = curl_slist_append(hdrs, "Connection: keep-alive");
            curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
        } else {
            struct curl_slist* h2 = curl_slist_append(nullptr, "Connection: keep-alive");
            hdrs = h2;
            curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
        }

        // 绑定共享对象（DNS/SSL/连接缓存）
        if (share_) curl_easy_setopt(c, CURLOPT_SHARE, share_);

        CURLcode rc = curl_easy_perform(c);
        long code = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);

        if (hdrs) { curl_slist_free_all(hdrs); hdrs = nullptr; }
        release(c);

        if (rc != CURLE_OK)
            throw std::runtime_error(std::string("HTTP fail: ") + curl_easy_strerror(rc));
        if (code >= 400)
            throw std::runtime_error("HTTP " + std::to_string(code));
        return resp;
    } catch (...) {
        if (hdrs) curl_slist_free_all(hdrs);
        // 失败的 handle 仍然归还（curl_easy_reset 会清理状态）
        release(c);
        throw;
    }
}

void HttpClient::warmup(const std::string& url) {
    // 发个轻量 HEAD/GET 把 DNS、TCP、TLS 全打通，结果写入共享缓存
    try {
        CURL* c = acquire();
        std::string sink;
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(c, CURLOPT_NOBODY, 1L);            // HEAD
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 8000L);
        curl_easy_setopt(c, CURLOPT_TCP_NODELAY, 1L);
        curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(c, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
        const auto& ca = get_ca_path();
        if (!ca.empty()) curl_easy_setopt(c, CURLOPT_CAINFO, ca.c_str());
        if (share_) curl_easy_setopt(c, CURLOPT_SHARE, share_);
        CURLcode rc = curl_easy_perform(c);
        if (rc == CURLE_OK) spdlog::info("HTTP warmup ok: {}", url);
        else spdlog::warn("HTTP warmup failed ({}): {}", url, curl_easy_strerror(rc));
        release(c);
    } catch (const std::exception& e) {
        spdlog::warn("HTTP warmup exception: {}", e.what());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ChartInfoCache
// ─────────────────────────────────────────────────────────────────────────
ChartInfoCache& ChartInfoCache::instance() {
    static ChartInfoCache c;
    return c;
}

std::optional<CachedChartInfo> ChartInfoCache::get(int32_t chart_id) const {
    std::shared_lock lk(mu_);
    auto it = idx_.find(chart_id);
    if (it == idx_.end()) return std::nullopt;
    auto now = std::chrono::steady_clock::now();
    if (now - it->second->second.fetched_at > kTtl) return std::nullopt;
    return it->second->second;
}

void ChartInfoCache::put(int32_t chart_id, const std::string& name) {
    std::unique_lock lk(mu_);
    auto it = idx_.find(chart_id);
    if (it != idx_.end()) {
        // 更新并提到队头
        it->second->second.name = name;
        it->second->second.fetched_at = std::chrono::steady_clock::now();
        lru_.splice(lru_.begin(), lru_, it->second);
        return;
    }
    if (lru_.size() >= kMaxEntries) {
        idx_.erase(lru_.back().first);
        lru_.pop_back();
    }
    CachedChartInfo info{chart_id, name, std::chrono::steady_clock::now()};
    lru_.emplace_front(chart_id, std::move(info));
    idx_[chart_id] = lru_.begin();
}

// ─────────────────────────────────────────────────────────────────────────
// HttpThreadPool
// ─────────────────────────────────────────────────────────────────────────
HttpThreadPool& HttpThreadPool::instance() {
    static HttpThreadPool pool;
    return pool;
}

HttpThreadPool::HttpThreadPool() {
    unsigned n = std::thread::hardware_concurrency();
    if (n == 0) n = 4;
    // HTTP I/O 是阻塞的，所以可以开比 CPU 核数更多的线程
    n = std::max(8u, n * 2);
    workers_.reserve(n);
    for (unsigned i = 0; i < n; i++)
        workers_.emplace_back(&HttpThreadPool::worker_loop, this);
    spdlog::info("HTTP thread pool started with {} workers", n);
}

HttpThreadPool::~HttpThreadPool() { stop(); }

void HttpThreadPool::stop() {
    if (stop_.exchange(true)) return;
    cv_.notify_all();
    for (auto& t : workers_) if (t.joinable()) t.join();
}

void HttpThreadPool::submit(std::function<void()> task) {
    if (stop_.load()) return;
    {
        std::lock_guard<std::mutex> lk(mu_);
        tasks_.push(std::move(task));
    }
    cv_.notify_one();
}

void HttpThreadPool::worker_loop() {
    while (!stop_.load()) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [this]{ return stop_.load() || !tasks_.empty(); });
            if (stop_.load() && tasks_.empty()) return;
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        try { task(); }
        catch (const std::exception& e) {
            spdlog::error("HTTP pool task threw: {}", e.what());
        } catch (...) {
            spdlog::error("HTTP pool task threw unknown");
        }
    }
}
