// ─────────────────────────────────────────────────────────────────────────
// http_client.hpp — 高性能 CURL HTTP 客户端，针对 phira-mp 服务器优化
//
// 解决问题：
//   1. 每次请求都新建 CURL handle、重做 TLS 握手 → 引入 handle 池
//   2. 多次请求同一 host 不复用连接 → CURLOPT_FORBID_REUSE=0 + CURLSH 共享
//   3. 每次都做 DNS 解析 → CURL_LOCK_DATA_DNS 共享 DNS 缓存
//   4. 每次都做 TLS 握手 → CURL_LOCK_DATA_SSL_SESSION 共享 SSL session
//   5. 首次 CA 路径搜索无线程安全 → std::call_once 保护
//   6. 每次 SelectChart 都回源 → 引入 LRU 谱面信息缓存
//   7. 每次 HTTP 都新建线程 → 引入固定大小 worker 线程池
// ─────────────────────────────────────────────────────────────────────────
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// 直接 include curl.h 而不是前向声明：
// 真正的 curl.h 中 CURL 与 CURLSH 的 typedef 定义可能与简单的前向声明冲突
// （某些版本是 typedef void CURL，有些是 typedef struct Curl_easy CURL），
// 引入 curl.h 让编译器使用权威定义即可。
#include <curl/curl.h>

// ── HTTP 客户端 ──────────────────────────────────────────────────────
class HttpClient {
public:
    // 进程内单例
    static HttpClient& instance();

    // 同步 GET（仍然阻塞调用线程，但复用 handle/连接/SSL session）
    // auth 可为空，否则作为 "Authorization: <auth>" 头发送
    std::string get(const std::string& url, const std::string& auth = "");

    // 立即触发对 phira host 的 TLS 握手预热（DNS+TCP+TLS 提前完成）
    // 服务器启动时调用一次即可
    void warmup(const std::string& url);

    // 显式停止，释放所有 handle 和 share
    void shutdown();

private:
    HttpClient();
    ~HttpClient();
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // 从池中取一个 CURL handle（无可用时新建）
    CURL* acquire();
    // 用完归还
    void release(CURL* h);

    void init_share();

    // CURL share 对象——跨 handle 共享 DNS 缓存与 SSL session
    CURLSH* share_ = nullptr;

    // handle 池
    std::mutex pool_mu_;
    std::vector<CURL*> pool_;
    static constexpr size_t kMaxPooled = 32;

    std::atomic<bool> shutdown_{false};
};

// ── CA 证书路径解析（线程安全，只算一次） ────────────────────────────
const std::string& get_ca_path();

// ── 谱面信息缓存：避免反复回源 phira.5wyxi.com ────────────────────────
struct CachedChartInfo {
    int32_t id;
    std::string name;
    std::chrono::steady_clock::time_point fetched_at;
};

class ChartInfoCache {
public:
    static ChartInfoCache& instance();

    // 命中返回非空 optional，未命中或过期返回 nullopt
    std::optional<CachedChartInfo> get(int32_t chart_id) const;

    // 写入或更新
    void put(int32_t chart_id, const std::string& name);

    // 缓存 TTL：5 分钟。谱面元信息变化频率极低，5 分钟足够安全。
    static constexpr std::chrono::seconds kTtl{300};
    // 上限，超出按 LRU 淘汰
    static constexpr size_t kMaxEntries = 4096;

private:
    ChartInfoCache() = default;
    mutable std::shared_mutex mu_;
    // 用 list 维护 LRU 顺序，map 索引到 list 节点
    using ListIt = std::list<std::pair<int32_t, CachedChartInfo>>::iterator;
    mutable std::list<std::pair<int32_t, CachedChartInfo>> lru_;
    std::unordered_map<int32_t, ListIt> idx_;
};

// ── 简单的 worker 线程池：避免每次 HTTP 都 std::thread+detach ─────────
class HttpThreadPool {
public:
    static HttpThreadPool& instance();
    void submit(std::function<void()> task);
    void stop();

private:
    HttpThreadPool();
    ~HttpThreadPool();
    HttpThreadPool(const HttpThreadPool&) = delete;
    HttpThreadPool& operator=(const HttpThreadPool&) = delete;

    void worker_loop();

    std::mutex mu_;
    std::condition_variable cv_;
    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    std::atomic<bool> stop_{false};
};
