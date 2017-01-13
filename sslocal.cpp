#include "Local.h"

int main(int argc, char *argv[]) {
    std::vector<Config> configs = parseCmdline(argc, argv);
    initLogging();
    boost::asio::io_service io_service;
    for (auto &config : configs) {
        std::make_shared<Local>(io_service, config)->run();
    }
    io_service.run();
    return 0;
}
