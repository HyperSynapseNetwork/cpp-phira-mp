#include "l10n.hpp"
#include "server.hpp"
#include "http_server.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <curl/curl.h>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <thread>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    // ── Parse args ────────────────────────────────────────────────────
    uint16_t port = 12346;
    uint16_t http_port = 12347;
    std::string admin_password = "admin";
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if ((a == "-p" || a == "--port") && i + 1 < argc) port = uint16_t(std::stoi(argv[++i]));
        else if ((a == "--http-port") && i + 1 < argc) http_port = uint16_t(std::stoi(argv[++i]));
        else if ((a == "--admin-password") && i + 1 < argc) admin_password = argv[++i];
        else if (a == "-h" || a == "--help") {
            std::cerr << "Usage: " << argv[0]
                      << " [--port PORT] [--http-port HTTP_PORT] [--admin-password PASSWORD]\n"
                      << "  --port           TCP game protocol port (default: 12346)\n"
                      << "  --http-port      HTTP API/admin port (default: 12347)\n"
                      << "  --admin-password Admin panel password (default: admin)\n";
            return 0;
        }
    }

    // ── Logging ───────────────────────────────────────────────────────
    try {
        std::string logdir = "log";
        if (auto e = std::getenv("HSN_LOGDIR")) logdir = e;
        if (!fs::exists(logdir)) fs::create_directory(logdir);
        auto con = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto file = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logdir + "/phira-mp.log", 10*1024*1024, 5);
        auto log = std::make_shared<spdlog::logger>("phira-mp", spdlog::sinks_init_list{con, file});
        if (auto e = std::getenv("RUST_LOG")) {
            std::string lv = e;
            if (lv == "trace") log->set_level(spdlog::level::trace);
            else if (lv == "debug") log->set_level(spdlog::level::debug);
            else if (lv == "info") log->set_level(spdlog::level::info);
            else if (lv == "warn") log->set_level(spdlog::level::warn);
            else if (lv == "error") log->set_level(spdlog::level::err);
        } else log->set_level(spdlog::level::info);
        spdlog::set_default_logger(log);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");
    } catch (const std::exception& e) { std::cerr << "Log init fail: " << e.what() << "\n"; return 1; }

    // ── Localization ──────────────────────────────────────────────────
    {
        std::string dir;
#ifdef LOCALES_DIR
        dir = LOCALES_DIR;
#endif
        if (dir.empty() || !fs::exists(dir)) dir = "locales";
        if (!fs::exists(dir)) dir = "/usr/share/phira-mp/locales";
        L10n::instance().load(dir);
    }

    curl_global_init(CURL_GLOBAL_ALL);
    spdlog::info("phira-mp-server starting");
    spdlog::info("  Game protocol port: {}", port);
    spdlog::info("  HTTP API/admin port: {}", http_port);
    std::cout << "Local Address: [::]:(" << port << " game, " << http_port << " http)\n";

    try {
        unsigned threads = std::thread::hardware_concurrency();
        if (!threads) threads = 4;
        asio::io_context ioc(threads);
#ifdef _WIN32
        asio::signal_set sigs(ioc, SIGINT);
#else
        asio::signal_set sigs(ioc, SIGINT, SIGTERM);
#endif
        sigs.async_wait([&](const error_code&, int s) { spdlog::info("Signal {}, shutting down", s); ioc.stop(); });

        // Game protocol server
        Server srv(ioc, port);
        srv.start();

        // HTTP server (API + admin panel + SSE)
        HttpServer http_srv(ioc, http_port, srv.state(), admin_password);
        srv.state()->sse_broadcaster = &http_srv.broadcaster();
        http_srv.start();

        std::vector<std::thread> workers;
        for (unsigned i = 1; i < threads; i++) workers.emplace_back([&]{ ioc.run(); });
        ioc.run();
        for (auto& t : workers) t.join();
    } catch (const std::exception& e) { spdlog::error("Fatal: {}", e.what()); curl_global_cleanup(); return 1; }
    curl_global_cleanup();
    spdlog::info("Server stopped");
    return 0;
}
