#include "config.h"
#include "rapidjson.h"
#include "document.h"

using namespace rapidjson;

DEFINE_string(s, "0.0.0.0", "host name or ip address of your remote server");
DEFINE_int32(p, 8388, "port number of your remote server");
DEFINE_string(b, "0.0.0.0", "local address to bind");
DEFINE_int32(l, 1080, "port number of your local server");
DEFINE_string(k, "secret", "password of your remote server");
DEFINE_string(m, "aes-256-cfb", "Encrypt method");
DEFINE_int32(t, 5, "timeout");
DEFINE_bool(u, false, "enable udprelay mode");
DEFINE_string(c, "", "json config path");
DEFINE_string(log, "", "log file path");
DEFINE_bool(autoban, false, "Auto ban evil clients");
DEFINE_bool(daemon, false, "Enable daemon mode");
DEFINE_bool(verbose, false, "Enable verbose mode");

std::unordered_set<std::string> ForbiddenIPAddresses;
std::unordered_map<std::string, int> EvilIPAddresses;

Config::Config() {
    ServerAddress = FLAGS_s;
    ServerPort = FLAGS_p;
    LocalAddress = FLAGS_b;
    LocalPort = FLAGS_l;
    Password = FLAGS_k;
    Method = FLAGS_m;
    Timeout = FLAGS_t;
    AutoBan = FLAGS_autoban;    
}

std::vector<Config> parseCmdline(int argc, char **argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    std::vector<Config> configs;
    if (FLAGS_c.empty()) {
        Config config;
        configs.emplace_back(config);
        return configs;
    }
    std::ifstream ifs(FLAGS_c);
    std::string jsonstr((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
    if (jsonstr.empty()) {
        return configs;
    }
    Document d;
    d.Parse(jsonstr.data());
    if (d.IsNull()) {
        return configs;
    }
    auto f = [&](decltype(d.GetObject()) j) {
        Config config;
        std::unordered_map<std::string, std::function<void(bool)>> boolean_handlers;
        std::unordered_map<std::string, std::function<void(int)>> integer_handlers;
        std::unordered_map<std::string, std::function<void(const std::string &)>> string_handlers;
        auto get_int_assigner = [&](const std::string &name, int *pi) {
            integer_handlers.insert(std::make_pair(name, [&, pi](int i) {
                *pi = i;
            }));
        };
        auto get_bool_assigner = [&](const std::string &name, bool *pb) {
            boolean_handlers.insert(std::make_pair(name, [&, pb](bool b) {
                *pb = b;
            }));
        };
        auto get_string_assigner = [&](const std::string &name, std::string *ps) {
            string_handlers.insert(std::make_pair(name, [&, ps](const std::string &s) {
                *ps = s;
            }));
        };
        int ServerPort = config.ServerPort;
        int LocalPort = config.LocalPort;
        int Timeout = config.Timeout;
        get_string_assigner("server", &config.ServerAddress);
        get_int_assigner("server_port", &ServerPort);
        get_string_assigner("local_address", &config.LocalAddress);
        get_int_assigner("local_port", &LocalPort);
        get_string_assigner("password", &config.Password);
        get_string_assigner("method", &config.Method);
        get_int_assigner("timeout", &Timeout);
        get_bool_assigner("autoban", &config.AutoBan);
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
        config.ServerPort = ServerPort;
        config.LocalPort = LocalPort;
        config.Timeout = Timeout;
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
