#pragma once
#include <map>
#include <string>
#include <vector>

enum class Lang { EnUS = 0, ZhCN = 1, ZhTW = 2 };

Lang parse_language(const std::string& s);

class L10n {
public:
    static L10n& instance();
    void load(const std::string& dir);
    std::string get(Lang lang, const std::string& key) const;
private:
    L10n() = default;
    std::vector<std::map<std::string, std::string>> bundles_;
};

class LangContext {
public:
    static void set(Lang l);
    static Lang get();
private:
    static thread_local Lang cur_;
};

#define TL(key) L10n::instance().get(LangContext::get(), key)
