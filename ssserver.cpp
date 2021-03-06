#include "Server.h"
#include "UdpServer.h"

void daemonize(asio::io_service &io_service)
{
    asio::signal_set signals(io_service, SIGINT, SIGTERM);
    signals.async_wait([&](std::error_code, int) { io_service.stop(); });
    io_service.notify_fork(asio::io_service::fork_prepare);
    if (pid_t pid = fork()) {
        if (pid > 0) {
            std::exit(0);
        } else {
            std::exit(1);
        }
    }
    setsid();
    chdir("/");
    umask(0);
    if (pid_t pid = fork()) {
        if (pid > 0) {
            std::exit(0);
        } else {
            std::exit(1);
        }
    }
    close(0);
    close(1);
    close(2);
    if (open("/dev/null", O_RDONLY) < 0) {
        std::exit(1);
    }

    if (!g_cfg.log.empty()) {
        const char *output = g_cfg.log.c_str();
        const int flags = O_WRONLY | O_CREAT | O_APPEND;
        const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        if (open(output, flags, mode) < 0) {
            std::exit(1);
        }
    } else {
        if (open("/dev/null", O_WRONLY) < 0) {
            std::exit(1);
        }
    }
    if (dup(1) < 0) {
        std::exit(1);
    }
    io_service.notify_fork(asio::io_service::fork_child);

    printf("Daemon started!\n");
    start_trim_thread(g_cfg.trim_memory_interval);
    io_service.run();
    printf("Daemon stopped!\n");
}

int main(int argc, char *argv[])
{
    std::vector<config> configs = parseCmdline(argc, argv);
    asio::io_service io_service;
    for (auto &config : configs) {
        std::make_shared<Server>(io_service, config)->run();
        std::make_shared<UdpServer>(io_service, config)->run();
    }
    if (checkDaemon()) {
        daemonize(io_service);
    } else {
        start_trim_thread(g_cfg.trim_memory_interval);
        io_service.run();
    }
    return 0;
}
