#include "l10n.hpp"
#include <fstream>
#include <algorithm>
#include <spdlog/spdlog.h>

thread_local Lang LangContext::cur_ = Lang::EnUS;
void LangContext::set(Lang l) { cur_ = l; }
Lang LangContext::get() { return cur_; }

Lang parse_language(const std::string& s) {
    std::string lo = s;
    std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
    if (lo.find("zh") != std::string::npos) {
        if (lo.find("tw") != std::string::npos || lo.find("hant") != std::string::npos) return Lang::ZhTW;
        return Lang::ZhCN;
    }
    return Lang::EnUS;
}

L10n& L10n::instance() { static L10n inst; return inst; }

void L10n::load(const std::string& dir) {
    const char* files[] = {"en-US.txt", "zh-CN.txt", "zh-TW.txt"};
    bundles_.resize(3);
    for (int i = 0; i < 3; i++) {
        std::ifstream f(dir + "/" + files[i]);
        if (!f.is_open()) { spdlog::warn("Cannot open locale: {}/{}", dir, files[i]); continue; }
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto eq = line.find('='); if (eq == std::string::npos) continue;
            auto key = line.substr(0, eq), val = line.substr(eq + 1);
            auto trim = [](std::string& s) {
                while (!s.empty() && std::isspace((unsigned char)s.front())) s.erase(s.begin());
                while (!s.empty() && std::isspace((unsigned char)s.back())) s.pop_back();
            };
            trim(key); trim(val); bundles_[i][key] = val;
        }
        spdlog::info("Loaded {} entries from {}", bundles_[i].size(), files[i]);
    }
}

std::string L10n::get(Lang lang, const std::string& key) const {
    int idx = int(lang); if (idx < 0 || idx >= int(bundles_.size())) idx = 0;
    auto it = bundles_[idx].find(key);
    if (it != bundles_[idx].end()) return it->second;
    if (idx != 0) { it = bundles_[0].find(key); if (it != bundles_[0].end()) return it->second; }
    return key;
}
