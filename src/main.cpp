#include "server.h"
#include "l10n.h"
#include "ban_manager.h"
#include "web_server.h"
#include "ws_server.h"
#include <iostream>
#include <csignal>
#include <cstdlib>
#include <cstring>

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [OPTIONS]" << std::endl;
    std::cerr << "  -p, --port PORT         Game server port (default: 12346)" << std::endl;
    std::cerr << "  -w, --web-port PORT     Web admin/API port (default: 12345)" << std::endl;
    std::cerr << "  -s, --wss-port PORT     WebSocket Secure port (default: 7785)" << std::endl;
    std::cerr << "  --tls-cert PATH         TLS certificate file (default: /etc/ssl/certs/server.crt)" << std::endl;
    std::cerr << "  --tls-key PATH          TLS private key file (default: /etc/ssl/private/server.key)" << std::endl;
    std::cerr << "  -h, --help              Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    uint16_t port = 12346;
    uint16_t web_port = 12345;
    uint16_t wss_port = 7785;

    // Parse command line args
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                i++;
                try {
                    int p = std::stoi(argv[i]);
                    if (p <= 0 || p > 65535) {
                        std::cerr << "Port must be between 1 and 65535" << std::endl;
                        return 1;
                    }
                    port = (uint16_t)p;
                } catch (...) {
                    std::cerr << "Invalid port number: " << argv[i] << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Missing port number after " << arg << std::endl;
                return 1;
            }
        } else if (arg == "-w" || arg == "--web-port") {
            if (i + 1 < argc) {
                i++;
                try {
                    int p = std::stoi(argv[i]);
                    if (p <= 0 || p > 65535) {
                        std::cerr << "Web port must be between 1 and 65535" << std::endl;
                        return 1;
                    }
                    web_port = (uint16_t)p;
                } catch (...) {
                    std::cerr << "Invalid web port number: " << argv[i] << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Missing port number after " << arg << std::endl;
                return 1;
            }
        } else if (arg == "-s" || arg == "--wss-port") {
            if (i + 1 < argc) {
                i++;
                try {
                    int p = std::stoi(argv[i]);
                    if (p <= 0 || p > 65535) {
                        std::cerr << "WSS port must be between 1 and 65535" << std::endl;
                        return 1;
                    }
                    wss_port = (uint16_t)p;
                } catch (...) {
                    std::cerr << "Invalid WSS port number: " << argv[i] << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Missing port number after " << arg << std::endl;
                return 1;
            }
        } else if (arg == "--tls-cert") {
            if (i + 1 < argc) {
                i++;
                g_tls_cert_path = argv[i];
            } else {
                std::cerr << "Missing path after --tls-cert" << std::endl;
                return 1;
            }
        } else if (arg == "--tls-key") {
            if (i + 1 < argc) {
                i++;
                g_tls_key_path = argv[i];
            } else {
                std::cerr << "Missing path after --tls-key" << std::endl;
                return 1;
            }
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    // Load localization files
    L10n::instance().load_from_directory("locales");

    // Load ban list
    BanManager::instance().load("banned.txt");

    // Ignore SIGPIPE (broken pipe on socket write)
    signal(SIGPIPE, SIG_IGN);

    std::cerr << "phira-mp-server (C++ port) with Web Admin, API & WSS" << std::endl;
    std::cerr << "Game Server:  [::]:" << port << std::endl;
    std::cerr << "Web Admin:    [::]:" << web_port << std::endl;
    std::cerr << "WSS Server:   [::]:" << wss_port << std::endl;
    std::cerr << "TLS Cert:     " << g_tls_cert_path << std::endl;
    std::cerr << "TLS Key:      " << g_tls_key_path << std::endl;
    std::cerr << "QQ Group:     1049578201" << std::endl;

    try {
        Server server(port);

        // Start web server (needs access to server state)
        WebServer web(web_port, server.get_state());
        g_web_server = &web;
        web.start();

        // Start WSS server for live touch/judge data
        WsServer wss(wss_port, server.get_state());
        g_ws_server = &wss;
        wss.start();

        server.run();

        g_ws_server = nullptr;
        g_web_server = nullptr;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
