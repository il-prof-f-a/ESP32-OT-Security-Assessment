#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

struct AllowConfig {
    // pointers to the LIVE vectors of your ConfigurationManager
    const std::vector<std::string>* allowed_ips = nullptr;
    const std::vector<std::string>* allowed_macs = nullptr;
    const std::vector<std::string>* whitelist_ips = nullptr;   // ip_whitelist.ip
    const std::vector<std::string>* whitelist_macs = nullptr;  // ip_whitelist.mac
};

// --- utils ---
inline std::string upper(const std::string& s) {
    std::string r(s);
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c){ return std::toupper(c); });
    return r;
}

inline std::string canon_mac(std::string mac) {
    mac = upper(mac);
    for (char& c : mac) if (c == '-') c = ':'; // normalize separator
    return mac;
}

inline bool wildcardMatch(const std::string& str, const std::string& pat) {
    size_t s = 0, p = 0, star = std::string::npos, ss = 0;
    while (s < str.size()) {
        if (p < pat.size() && (pat[p] == '?' || pat[p] == str[s])) { ++s; ++p; }
        else if (p < pat.size() && pat[p] == '*') { star = p++; ss = s; }
        else if (star != std::string::npos) { p = star + 1; s = ++ss; }
        else return false;
    }
    while (p < pat.size() && pat[p] == '*') ++p;
    return p == pat.size();
}

inline bool anyMatch(const std::string& needle,
                     const std::vector<std::string>* hay,
                     bool mac = false)
{
    if (!hay) return false;
    std::string n = mac ? canon_mac(needle) : upper(needle);
    for (const auto& x : *hay) {
        std::string pat = mac ? canon_mac(x) : upper(x);
        if (wildcardMatch(n, pat)) return true;
        if (n == pat) return true;
    }
    return false;
}

// --- policy ---
inline bool is_sender_allowed(const std::string& src_ip,
                              const std::string& src_mac,
                              const std::string& proto_upper,
                              const AllowConfig& cfg)
{
    const bool mac_ok =
        anyMatch(src_mac, cfg.allowed_macs, /*mac*/true) ||
        anyMatch(src_mac, cfg.whitelist_macs, /*mac*/true) ||
        canon_mac(src_mac) == "FF:FF:FF:FF:FF:FF" ||           // broadcast
        canon_mac(src_mac).rfind("01:00:5E:",0)==0 ||          // IPv4 mcast
        canon_mac(src_mac).rfind("33:33:",0)==0 ||             // IPv6 mcast
        canon_mac(src_mac).rfind("01:80:C2:",0)==0 ||          // L2 control
        canon_mac(src_mac).rfind("01:0E:CF:",0)==0;            // Profinet DCP

    const bool has_ip = !src_ip.empty() && src_ip != "0.0.0.0";
    const bool ip_ok = has_ip && (
        anyMatch(src_ip, cfg.allowed_ips) ||
        anyMatch(src_ip, cfg.whitelist_ips) ||
        src_ip == "255.255.255.255" ||
        src_ip.rfind("224.",0)==0 || src_ip.rfind("239.",0)==0
    );

    if (!has_ip) return mac_ok;       // MAC only for L2 frames
    return mac_ok || ip_ok;           // IP present: either one is enough
}
