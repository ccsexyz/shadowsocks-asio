#include "utils.h"
#include "config.h"
#include "encrypt.h"

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

void initLogging() {
    if (!LogFilePath.empty()) {
        logging::add_file_log(LogFilePath);
    }
    if (IsVerboseMode) {
        logging::core::get()->set_filter(logging::trivial::severity >=
                                         logging::trivial::debug);
    } else if (IsQuietMode) {
        logging::core::get()->set_filter(logging::trivial::severity >=
                                         logging::trivial::warning);
    } else {
        logging::core::get()->set_filter(logging::trivial::severity >=
                                         logging::trivial::info);
    }
}

bool checkAddress(std::string address) {
    auto it = ForbiddenIPAddresses.find(address);
    if (it == ForbiddenIPAddresses.end()) {
        return true;
    } else {
        return false;
    }
}

void runAfter(boost::asio::io_service &io_service,
              boost::posix_time::time_duration td, functor f) {
    auto dt = std::make_shared<boost::asio::deadline_timer>(io_service, td);
    dt->async_wait([dt, f](const boost::system::error_code &) { f(); });
}

std::size_t getRandomNumber() {
    static std::random_device rd;
    return rd();
}

std::unique_ptr<BaseEncrypter> getEncrypter(const std::string &method,
                                            const std::string &pwd) {
    if (method == "aes-128-cfb") {
        return std::move(std::make_unique<Encrypter<AES, 16, 16>>(pwd));
    } else if (method == "aes-192-cfb") {
        return std::move(std::make_unique<Encrypter<AES, 24, 16>>(pwd));
    } else if (method == "des-cfb") {
        return std::move(std::make_unique<Encrypter<DES, 8, 8>>(pwd));
    } else if (method == "bf-cfb") {
        return std::move(std::make_unique<Encrypter<Blowfish, 16, 8>>(pwd));
    } else if (method == "chacha20") {
        return std::move(std::make_unique<Encrypter<ChaCha20, 32, 8>>(pwd));
    } else if (method == "salsa20") {
        return std::move(std::make_unique<Encrypter<Salsa20, 32, 8>>(pwd));
    } else {
        return std::move(std::make_unique<Encrypter<AES, 32, 16>>(pwd));
    }
}

std::unique_ptr<BaseDecrypter> getDecrypter(const std::string &method,
                                            const std::string &pwd) {
    if (method == "aes-128-cfb") {
        return std::move(std::make_unique<Decrypter<AES, 16, 16>>(pwd));
    } else if (method == "aes-192-cfb") {
        return std::move(std::make_unique<Decrypter<AES, 24, 16>>(pwd));
    } else if (method == "des-cfb") {
        return std::move(std::make_unique<Decrypter<DES, 8, 8>>(pwd));
    } else if (method == "bf-cfb") {
        return std::move(std::make_unique<Decrypter<Blowfish, 16, 8>>(pwd));
    } else if (method == "chacha20") {
        return std::move(std::make_unique<Decrypter<ChaCha20, 32, 8>>(pwd));
    } else if (method == "salsa20") {
        return std::move(std::make_unique<Decrypter<Salsa20, 32, 8>>(pwd));
    } else {
        return std::move(std::make_unique<Decrypter<AES, 32, 16>>(pwd));
    }
}

void plusOneSecond(boost::asio::io_service &service,
                   boost::asio::ip::tcp::socket &&s) {
    std::size_t n = 0;
    std::size_t x = 0;
    do {
        x = getRandomNumber() % 16 + 1;
        n += x;
    } while (x < 3 || x > 14);
    BOOST_LOG_TRIVIAL(trace) << "续了 " << n << " 秒";
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(std::move(s));
    runAfter(service, boost::posix_time::seconds(n), [socket] {});
}

static std::unordered_map<std::string, std::tuple<std::size_t, std::size_t>>
    keyIvLens = {{"aes-128-cfb", {16, 16}},
                 {"aes-192-cfb", {24, 16}},
                 {"aes-256-cfb", {32, 16}},
                 {"des-cfb", {8, 8}},
                 {"bf-cfb", std::tuple<std::size_t, std::size_t>(16, 8)},
                 {"cast5-cfb", {16, 8}},
                 {"rc4-md5", {16, 16}},
                 {"chacha20", {32, 8}},
                 {"salsa20", {32, 8}}};
