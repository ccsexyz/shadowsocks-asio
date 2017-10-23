#include "config.h"
#include "json.hpp"

using json = nlohmann::json;

// bool IsOta;
bool IsFastOpen;
bool IsDaemon;
std::string PidFilePath;
std::string LogFilePath;
std::string Username;
bool IsVerboseMode;
bool IsQuietMode;
bool ShowVersion;
bool ShowHelpMessage;
std::unordered_set<std::string> ForbiddenIPAddresses;
std::unordered_map<std::string, int> EvilIPAddresses;

void testJson() {
    auto j = json::parse("{\"hello\":\"world\"}");
    for (auto it = j.cbegin(); it != j.cend(); ++it) {
        std::cout << it.key() << ":" << it.value().get<int>() << std::endl;
    }
}

std::vector<Config> parseCmdline(int argc, char **argv) {
    std::string ConfigFilePath;
    std::vector<Config> configs;
    std::vector<std::string> cmdlines;
    for (int i = 1; i < argc; i++) {
        cmdlines.emplace_back(argv[i]);
    }
    cmdlines.emplace_back("");
    Config config;
    std::string s;
    std::unordered_map<std::string, std::function<void()>> handlers = {
        {"-c", [&] { ConfigFilePath = s; }},
        {"-s", [&] { config.ServerAddress = s; }},
        {"-p", [&] { config.ServerPort = (uint16_t)std::stoul(s); }},
        {"-b", [&] { config.LocalAddress = s; }},
        {"-l", [&] { config.LocalPort = (uint16_t)std::stoul(s); }},
        {"-k", [&] { config.Password = s; }},
        {"-m", [&] { config.Method = s; }},
        {"-t", [&] { config.Timeout = (uint32_t)std::stoul(s); }},
        //        {"-a", [&] { config.IsOta = true; }},
        {"--fast--open", [&] { config.IsFastOpen = true; }},
        {"--forbidden-ip",
         [&] {
             std::string ip = "";
             for (auto &c : s) {
                 if (c == ',') {
                     if (ip != "") {
                         ForbiddenIPAddresses.insert(ip);
                     }
                 } else {
                     ip += c;
                 }
             }
         }},
        {"--auto-ban", [&] { config.AutoBan = true; }},
        {"--prefer-ipv6", [&] { config.PreferIPv6 = true; }},
        {"-h", [&] { ShowHelpMessage = true; }},
        {"--help", [&] { ShowHelpMessage = true; }},
        {"--pid-file", [&] { PidFilePath = s; }},
        {"--log-file", [&] { LogFilePath = s; }},
        {"-v", [&] { IsVerboseMode = true; }},
        {"-vv", [&] { IsVerboseMode = true; }},
        {"-q", [&] { IsQuietMode = true; }},
        {"-qq", [&] { IsQuietMode = true; }},
        {"--version", [&] { ShowVersion = true; }},
        {"", [&] {}}};
    std::unordered_set<std::string> ons = {
        "-a",  "--fast-open", "-h",  "--help",    "--prefer-ipv6", "-v",
        "-vv", "-q",          "-qq", "--version", "--auto-ban",    ""};
    auto size = cmdlines.size();
    for (size_t i = 0; i < size; i++) {
        auto fit = handlers.find(cmdlines[i]);
        if (fit != handlers.end()) {
            if (ons.find(cmdlines[i]) == ons.end()) {
                s = cmdlines[i + 1];
                i++;
            }
            (fit->second)();
        }
    }
    if (ConfigFilePath.empty() || config != Config()) {
        configs.emplace_back(std::move(config));
    }
    if (ConfigFilePath.empty()) {
        return configs;
    }
    std::ifstream ifs(ConfigFilePath);
    std::string jsonstr((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
    if (jsonstr.empty()) {
        return configs;
    }
    auto j = json::parse(jsonstr);
    using json_type = decltype(j);
    if (j.is_null() || (!j.is_object() || !j.is_array())) {
        return configs;
    }
    std::unordered_map<std::string, std::function<void(json_type)>> functors = {
        {"server",
         [&](json_type value) {
             if (value.is_string()) {
                 auto server = value.get<std::string>();
                 if (!server.empty()) {
                     config.ServerAddress = server;
                 }
             }
         }},
        {"server_port",
         [&](json_type value) {
             if (value.is_number_unsigned()) {
                 auto server_port = value.get<uint32_t>();
                 if (server_port <= 65536) {
                     config.ServerPort = server_port;
                 }
             }
         }},
        {"local_address",
         [&](json_type value) {
             if (value.is_string()) {
                 auto local_address = value.get<std::string>();
                 if (!local_address.empty()) {
                     config.LocalAddress = local_address;
                 }
             }
         }},
        {"local_port",
         [&](json_type value) {
             if (value.is_number_unsigned()) {
                 auto local_port = value.get<uint32_t>();
                 if (local_port <= 65536) {
                     config.LocalPort = local_port;
                 }
             }
         }},
        {"password",
         [&](json_type value) {
             if (value.is_string()) {
                 auto password = value.get<std::string>();
                 if (!password.empty()) {
                     config.Password = password;
                 }
             }
         }},
        {"timeout",
         [&](json_type value) {
             if (value.is_number_unsigned()) {
                 auto timeout = value.get<uint32_t>();
                 config.Timeout = timeout;
             }
         }},
        {"method",
         [&](json_type value) {
             if (value.is_string()) {
                 auto method = value.get<std::string>();
                 if (!method.empty()) {
                     config.Method = method;
                 }
             }
         }},
        {"fast_open",
         [&](json_type value) {
             if (value.is_boolean()) {
                 auto fast_open = value.get<bool>();
                 config.IsFastOpen = fast_open;
             }
         }},
        {"autoban",
         [&](json_type value) {
             if (value.is_boolean()) {
                 auto autoban = value.get<bool>();
                 config.AutoBan = autoban;
             }
         }},
        {"forbidden_ips", [&](json_type value) {
             if (value.is_array()) {
                 for (auto it = value.cbegin(); it != value.cend(); ++it) {
                     auto v = *it;
                     if (v.is_string()) {
                         auto ip = v.get<std::string>();
                         if (!ip.empty()) {
                             ForbiddenIPAddresses.insert(ip);
                         }
                     }
                 }
             }
         }}};
    auto f = [&](json_type j) {
        config = Config();
        for (auto it = j.cbegin(); it != j.cend(); ++it) {
            auto key = it.key();
            auto value = it.value();
            if (functors.find(key) != functors.end()) {
                functors[key](value);
            }
        }
        configs.emplace_back(std::move(config));
    };
    if (j.is_array()) {
        for (auto it = j.cbegin(); it != j.cend(); ++it) {
            auto v = *it;
            if (v.is_object()) {
                f(v);
            }
        }
    } else {
        f(j);
    }
    return configs;
}
