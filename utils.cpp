#include "utils.h"
#include "config.h"
#include "encrypt.h"

#ifdef __linux__
#include "malloc.h"
#endif

void printVersion()
{
    printf("shadowsocks-asio 0.0.1\n");
    std::exit(0);
}

bool checkDaemon()
{
    if (!g_cfg.daemon) {
        return false;
    }
    if (g_cfg.log.empty()) {
        printf("You should set the log file\n");
    }
    return true;
}

bool checkAddress(std::string address)
{
    auto it = ForbiddenIPAddresses.find(address);
    if (it == ForbiddenIPAddresses.end()) {
        return true;
    } else {
        return false;
    }
}

void runAfter(asio::io_service &io_service, asio::high_resolution_timer::duration td, functor f)
{
    auto dt = std::make_shared<asio::high_resolution_timer>(io_service, td);
    dt->async_wait([dt, f](const std::error_code &) { f(); });
}

std::size_t getRandomNumber()
{
    static std::random_device rd;
    return rd();
}

void plusOneSecond(asio::io_service &service, asio::ip::tcp::socket &&s)
{
    std::size_t n = 0;
    std::size_t x = 0;
    do {
        x = getRandomNumber() % 16 + 1;
        n += x;
    } while (x < 3 || x > 14);
    log_debug("续了 %zu 秒", n);
    auto socket = std::make_shared<asio::ip::tcp::socket>(std::move(s));
    runAfter(service, std::chrono::seconds(n), [socket] {});
}

#ifdef __linux__
static void trim_memory()
{
    struct timeval tv = tv_now();
    int rc = malloc_trim(0);
    double ms_taken = tv_sub_msec_double(tv_now(), tv);
    log_info("malloc_trim taken %.2fms", ms_taken);
}
#endif

void start_trim_thread(int interval)
{
    if (interval <= 0) {
        return;
    }

#ifdef __linux__
    std::thread t([] (int interval) {
        while (1) {
            std::this_thread::sleep_for(std::chrono::seconds(interval));
            trim_memory();
        }
    }, interval);
    t.detach();
#else
    log_alert("malloc_trim is not supported!");
#endif
}
