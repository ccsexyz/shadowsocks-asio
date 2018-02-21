#include "Server.h"
#include "UdpServer.h"

void printHelpMessage() {
    printf(
        "usage: ssserver [OPTION]...\n"
        "A fast tunnel proxy that helps you bypass firewalls.\n\n"

        "You can supply configurations via either config file or command line "
        "arguments.\n\n"

        "Proxy options:\n"
        "  -c CONFIG              path to config file\n"
        "  -s SERVER_ADDR         server address, default: 0.0.0.0\n"
        "  -p SERVER_PORT         server port, default: 8388\n"
        "  -k PASSWORD            password\n"
        "  -m METHOD              encryption method, default: aes-256-cfb\n"
        "  -t TIMEOUT             timeout in seconds, default: 300\n"
        "  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+\n"
        "  --forbidden-ip IPLIST  comma seperated IP list forbidden to "
        "connect\n\n"
        "  --prefer-ipv6          resolve ipv6 address first\n\n"

        "General options:\n"
        "  -h, --help             show this help message and exit\n"
        "  -d start/stop/restart  daemon mode\n"
        "  --pid-file PID_FILE    pid file for daemon mode\n"
        "  --log-file LOG_FILE    log file for daemon mode\n"
        "  --user USER            username to run as\n"
        "  -v, -vv                verbose mode\n"
        "  -q, -qq                quiet mode, only show warnings/errors\n"
        "  --version              show version information\n\n"
        "Note: this server won't support ota\n");
    std::exit(0);
}

void daemonize(asio::io_service &io_service) {
    asio::signal_set signals(io_service, SIGINT, SIGTERM);
    signals.async_wait(
        [&](std::error_code, int) { io_service.stop(); });
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

    if (!LogFilePath.empty()) {
        const char *output = LogFilePath.c_str();
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
    io_service.run();
    printf("Daemon stopped!\n");
}

int main(int argc, char *argv[]) {
    std::vector<Config> configs = parseCmdline(argc, argv);
    if (ShowHelpMessage) {
        printHelpMessage();
    }
    if (ShowVersion) {
        printVersion();
    }
    asio::io_service io_service;
    for (auto &config : configs) {
        std::make_shared<Server>(io_service, config)->run();
        std::make_shared<UdpServer>(io_service, config)->run();
    }
    auto attributes = boost::coroutines::attributes();
    LOG(INFO) << "boost coroutine stack size " << attributes.size;
    if (checkDaemon()) {
        daemonize(io_service);
    } else {
        io_service.run();
    }
    return 0;
}
