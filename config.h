#ifndef SHADOWSOCKS_ASIO_CONFIG_H
#define SHADOWSOCKS_ASIO_CONFIG_H

#include "utils.h"

DECLARE_string(log);
DECLARE_bool(daemon);
DECLARE_bool(verbose);

extern std::unordered_set<std::string> ForbiddenIPAddresses;
extern std::unordered_map<std::string, int> EvilIPAddresses;

class Config final {
public:
    Config();
    std::string ServerAddress;
    std::uint16_t ServerPort;
    std::string LocalAddress;
    std::uint16_t LocalPort;
    std::string Password;
    std::string Method;
    std::uint32_t Timeout;
    bool AutoBan;

    bool IsFastOpen = false;
    bool PreferIPv6 = false;
};

static inline bool operator==(const Config &left, const Config &right) {
    return left.ServerAddress == right.ServerAddress &&
           left.ServerPort == right.ServerPort &&
           left.LocalAddress == right.LocalAddress &&
           left.LocalPort == right.LocalPort &&
           left.Password == right.Password && left.Method == right.Method &&
           left.Timeout == right.Timeout &&
           left.IsFastOpen == right.IsFastOpen &&
           left.PreferIPv6 == right.PreferIPv6;
}

static inline bool operator!=(const Config &left, const Config &right) {
    return !(right == left);
}

std::vector<Config> parseCmdline(int argc, char **argv);

void testJson();

#endif // SHADOWSOCKS_ASIO_CONFIG_H
