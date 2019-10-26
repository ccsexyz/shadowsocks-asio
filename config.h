#ifndef SHADOWSOCKS_ASIO_CONFIG_H
#define SHADOWSOCKS_ASIO_CONFIG_H

#include "utils.h"

extern std::unordered_set<std::string> ForbiddenIPAddresses;
extern std::unordered_map<std::string, int> EvilIPAddresses;

struct config {
    std::string remote_addr;
    int remote_port;
    std::string local_addr;
    int local_port;
    std::string password;
    std::string method;
    int timeout;
    int udprelay;
    std::string config;
    std::string log;
    int autoban;
    int daemon;
    int verbose;
    int prefer_ipv6;
    int trim_memory_interval;
};

extern config g_cfg;

/*
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
*/

std::vector<config> parseCmdline(int argc, char **argv);

void testJson();

#endif // SHADOWSOCKS_ASIO_CONFIG_H
