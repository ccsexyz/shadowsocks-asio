#include "Local.h"

int main(int argc, char *argv[]) {
    google::LogToStderr();
    google::InitGoogleLogging(argv[0]);
    std::vector<Config> configs = parseCmdline(argc, argv);
    asio::io_service io_service;
    for (auto &config : configs) {
        std::make_shared<Local>(io_service, config)->run();
    }
    io_service.run();
    google::ShutdownGoogleLogging();
    return 0;
}
