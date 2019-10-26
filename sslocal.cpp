#include "Local.h"

int main(int argc, char *argv[])
{
    std::vector<config> configs = parseCmdline(argc, argv);
    asio::io_service io_service;
    for (auto &config : configs) {
        std::make_shared<Local>(io_service, config)->run();
    }
    start_trim_thread(g_cfg.trim_memory_interval);
    io_service.run();
    return 0;
}
