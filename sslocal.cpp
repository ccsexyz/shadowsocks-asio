#include "Local.h"

int main(int argc, char *argv[]) {
    google::LogToStderr();
    google::InitGoogleLogging(argv[0]);
    std::vector<Config> configs = parseCmdline(argc, argv);
    if (!FLAGS_log.empty()) {
        google::SetLogDestination(0, FLAGS_log.c_str());
    }
    asio::io_service io_service;
    for (auto &config : configs) {
        std::make_shared<Local>(io_service, config)->run();
    }
    io_service.run();
    gflags::ShutDownCommandLineFlags();
    google::ShutdownGoogleLogging();
    return 0;
}
