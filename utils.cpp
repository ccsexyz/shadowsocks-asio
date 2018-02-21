#include "utils.h"
#include "config.h"
#include "encrypt.h"

boost::coroutines::attributes default_coroutines_attr = boost::coroutines::attributes(128 * 1024);

void printVersion() {
    printf("shadowsocks-asio 0.0.1\n");
    std::exit(0);
}

bool checkDaemon() {
    if (!IsDaemon) {
        return false;
    }
    if (PidFilePath.empty()) {
        printf("Cannot daemonize process without pidfile\n");
        IsDaemon = false;
        return false;
    }
    if (LogFilePath.empty()) {
        printf("You should set the log file\n");
    }
    return true;
}

// void initLogging() {
//     if (!LogFilePath.empty()) {
//         setLogFile(LogFilePath);
//     }
//     if (IsVerboseMode) {
//         setLogLevel(VERBOSE);
//     } else if (IsQuietMode) {
//         setLogLevel(WARN);
//     } else {
//         setLogLevel(INFO);
//     }
// }

bool checkAddress(std::string address) {
    auto it = ForbiddenIPAddresses.find(address);
    if (it == ForbiddenIPAddresses.end()) {
        return true;
    } else {
        return false;
    }
}

void runAfter(asio::io_service &io_service,
              boost::posix_time::time_duration td, functor f) {
    auto dt = std::make_shared<asio::deadline_timer>(io_service, td);
    dt->async_wait([dt, f](const std::error_code &) { f(); });
}

std::size_t getRandomNumber() {
    static std::random_device rd;
    return rd();
}

void plusOneSecond(asio::io_service &service,
                   asio::ip::tcp::socket &&s) {
    std::size_t n = 0;
    std::size_t x = 0;
    do {
        x = getRandomNumber() % 16 + 1;
        n += x;
    } while (x < 3 || x > 14);
    LOG(INFO) << "续了" << n << "秒";
    auto socket = std::make_shared<asio::ip::tcp::socket>(std::move(s));
    runAfter(service, boost::posix_time::seconds(n), [socket] {});
}

void AsioCondVar::wait(asio::io_service &io_service, asio::yield_context yield) {
    std::error_code ec;
    while(!ec) {
        auto timer = std::make_shared<asio::high_resolution_timer>(io_service);
        timer->expires_from_now(std::chrono::seconds(36000));
        timers_.push_back(timer);
        timer->async_wait(yield[ec]);
    }
}

void AsioCondVar::notify_one() {
    auto it = timers_.begin();
    if (it == timers_.end()) {
        return;
    }
    auto timer = (*it).lock();
    if (!timer) {
        timers_.pop_front();
        return;
    }
    timers_.pop_front();
    timer->cancel();
}

void AsioCondVar::notify_all() {
    while (!timers_.empty()) {
        notify_one();
    }
}

void AsioCondVar::notify_n(std::size_t n) {
    while (n-- > 0) {
        notify_one();
    }
}
