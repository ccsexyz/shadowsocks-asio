#ifndef SHADOWSOCKS_ASIO_CONFIG_H
#define SHADOWSOCKS_ASIO_CONFIG_H

#include "utils.h"

// extern bool IsOta; // I have no plan to implement one time auth
extern bool IsFastOpen;
extern bool IsDaemon;
extern std::string PidFilePath;
extern std::string LogFilePath;
extern std::string Username;
extern bool IsVerboseMode;
extern bool IsQuietMode;
extern bool ShowVersion;
extern bool ShowHelpMessage;
extern std::unordered_set<std::string> ForbiddenIPAddresses;
extern std::unordered_map<std::string, int> EvilIPAddresses;

class Config final {
public:
    std::string ServerAddress = "0.0.0.0";
    std::uint16_t ServerPort = 10000;
    std::string LocalAddress = "0.0.0.0";
    std::uint16_t LocalPort = 1080;
    std::string Password = "secret";
    std::string Method = "aes-256-cfb";
    std::uint32_t Timeout = 300;
    //    bool IsOta = false;
    bool IsFastOpen = false;
    bool PreferIPv6 = false;
    bool AutoBan = false;
};

static inline bool operator==(const Config &left, const Config &right) {
    return left.ServerAddress == right.ServerAddress &&
           left.ServerPort == right.ServerPort &&
           left.LocalAddress == right.LocalAddress &&
           left.LocalPort == right.LocalPort &&
           left.Password == right.Password && left.Method == right.Method &&
           left.Timeout == right.Timeout &&
           //           left.IsOta == right.IsOta &&
           left.IsFastOpen == right.IsFastOpen &&
           left.PreferIPv6 == right.PreferIPv6;
}

static inline bool operator!=(const Config &left, const Config &right) {
    return !(right == left);
}

std::vector<Config> parseCmdline(int argc, char **argv);

void testJson();

#endif // SHADOWSOCKS_ASIO_CONFIG_H
