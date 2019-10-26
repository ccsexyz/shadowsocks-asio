#include "config.h"
#include "document.h"
#include "rapidjson.h"

using namespace rapidjson;

static int ss_set_cxxstr(void *p, const char *value, char **errstr)
{
    assert(value);

    std::string *old_str = (std::string *)p;
    *old_str = value;

    return 0;
}

static command_t cmds[] = { { "s", "remote_addr", ss_set_cxxstr, offsetof(config, remote_addr),
                                "0.0.0.0", "host name or ip address of your remote server" },
    { "p", "remote_port", cmd_set_int, offsetof(config, remote_port), "8388",
        "port number of your remote server" },
    { "b", "local_addr", ss_set_cxxstr, offsetof(config, local_addr), "0.0.0.0",
        "local address to bind" },
    { "l", "local_port", cmd_set_int, offsetof(config, local_port), "1080",
        "port number of your local server" },
    { "k", "key", ss_set_cxxstr, offsetof(config, password), "secret",
        "password of your remote server" },
    { "m", "method", ss_set_cxxstr, offsetof(config, method), "aes-256-cfb", "encrypt method" },
    { "v", "verbose", nullptr, offsetof(config, verbose), "", "output verbose log" },
    { "d", "daemon", nullptr, offsetof(config, daemon), "enable daemon mode" },
    { "", "autoban", nullptr, offsetof(config, autoban), "auto ban evil clients" },
    { "", "log", ss_set_cxxstr, offsetof(config, log), "", "log file path" },
    { "c", "config", ss_set_cxxstr, offsetof(config, config), "", "json config path" },
    { "", "prefer_ipv6", nullptr, offsetof(config, prefer_ipv6), "", "prefer ipv6 address" },
    { "", "trim_interval", cmd_set_int, offsetof(config, trim_memory_interval), "60",
        "trim memory interval, in seconds" },
    { "u", "udp", nullptr, offsetof(config, udprelay), "", "enable udprelay mode" } };

config g_cfg;

std::unordered_set<std::string> ForbiddenIPAddresses;
std::unordered_map<std::string, int> EvilIPAddresses;

std::vector<config> parseCmdline(int argc, char **argv)
{
    std::vector<config> configs;

    char *errstr = NULL;
    int rc = parse_command_args(
        argc, (const char **)argv, &g_cfg, cmds, array_size(cmds), &errstr, nullptr);
    if (rc != 0) {
        log_fatal("parse command error: %s", errstr ? errstr : "-");
    }
    free(errstr);

    bool no_json_config = g_cfg.config.empty();
    if (no_json_config) {
        configs.emplace_back(g_cfg);
        return configs;
    }

    std::ifstream ifs(g_cfg.config);
    std::string jsonstr((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (jsonstr.empty()) {
        configs.emplace_back(g_cfg);
        return configs;
    }

    Document d;
    d.Parse(jsonstr.data());
    if (d.IsNull()) {
        configs.emplace_back(g_cfg);
        return configs;
    }
    auto f = [&](decltype(d.GetObject()) j) {
        config config;
        std::unordered_map<std::string, std::function<void(bool)>> boolean_handlers;
        std::unordered_map<std::string, std::function<void(int)>> integer_handlers;
        std::unordered_map<std::string, std::function<void(const std::string &)>> string_handlers;
        auto get_int_assigner = [&](const std::string &name, int *pi) {
            integer_handlers.insert(std::make_pair(name, [&, pi](int i) { *pi = i; }));
        };
        auto get_bool_assigner = [&](const std::string &name, int *pb) {
            boolean_handlers.insert(std::make_pair(name, [&, pb](bool b) { *pb = b; }));
        };
        auto get_string_assigner = [&](const std::string &name, std::string *ps) {
            string_handlers.insert(
                std::make_pair(name, [&, ps](const std::string &s) { *ps = s; }));
        };
        int ServerPort = config.remote_port;
        int LocalPort = config.local_port;
        int Timeout = config.timeout;
        get_string_assigner("server", &config.remote_addr);
        get_int_assigner("server_port", &ServerPort);
        get_string_assigner("local_address", &config.local_addr);
        get_int_assigner("local_port", &LocalPort);
        get_string_assigner("password", &config.password);
        get_string_assigner("method", &config.method);
        get_int_assigner("timeout", &Timeout);
        get_bool_assigner("autoban", &config.autoban);
        for (auto &m : j) {
            if (!m.name.IsString()) {
                continue;
            }
            auto key = m.name.GetString();
            auto &value = m.value;
            if (value.IsBool()) {
                auto it = boolean_handlers.find(key);
                if (it != boolean_handlers.end()) {
                    (it->second)(value.GetBool());
                }
            } else if (value.IsString()) {
                auto it = string_handlers.find(key);
                if (it != string_handlers.end()) {
                    (it->second)(value.GetString());
                }
            } else if (value.IsNumber()) {
                auto it = integer_handlers.find(key);
                if (it != integer_handlers.end()) {
                    (it->second)(value.GetInt());
                }
            }
        }
        config.remote_port = ServerPort;
        config.local_port = LocalPort;
        config.timeout = Timeout;
        configs.emplace_back(config);
    };
    if (d.IsArray()) {
        for (auto &o : d.GetArray()) {
            if (o.IsObject()) {
                f(o.GetObject());
            }
        }
    } else if (d.IsObject()) {
        f(d.GetObject());
    }
    return configs;
}
