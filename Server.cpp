#include "Server.h"

Server::Server(asio::io_service &io_service, const Config &config)
    : config_(config), service_(io_service), socket_(io_service),
      acceptor_(io_service,
                asio::ip::tcp::endpoint(
                    asio::ip::address::from_string(config.ServerAddress),
                    config.ServerPort)),
      resolver_(io_service) {}

void Server::run() {
    auto self = shared_from_this();
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    asio::spawn(service_, [this, self](asio::yield_context yield){
        while(1) {
            std::error_code ec;
            acceptor_.async_accept(socket_, yield[ec]);
            if (ec) {
                return;
            }
            auto endpoint = socket_.remote_endpoint();
            auto address = endpoint.address().to_string();
            bool ok = checkAddress(address);
            if (!ok) {
                plusOneSecond(service_, std::move(socket_));
                return;
            }
            std::make_shared<ServerSession>(service_, std::move(socket_), config_)->run();
        }
    });
}

ServerSession::ServerSession(asio::io_service &io_service,
                             asio::ip::tcp::socket &&socket,
                             Config &config)
    : config_(config), service_(io_service), strand_(io_service),
      socket_(std::move(socket)), rsocket_(io_service),
      resolver_(io_service), timer_(io_service) {}

void ServerSession::run() {
    auto self = shared_from_this();
    enc_ = getEncrypter(config_.Method, config_.Password);
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        while(socket_.is_open()) {
            std::error_code ec;
            timer_.async_wait(yield[ec]);
            if (timer_.expires_from_now() <= std::chrono::seconds(0)) {
                socket_.close();
            }
        }
    });
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        do_read_request(yield);
    });
}

void ServerSession::destroyLater() {
    plusOneSecond(service_, std::move(socket_));
}

void ServerSession::decrypt(char *b, std::size_t n) {
    if (b == nullptr || n == 0) {
        return;
    }
    std::string dst = dec_->decrypt(std::string(b, n));
    std::copy_n(dst.cbegin(), dst.length(), b);
}

void ServerSession::encrypt(char *b, std::size_t n) {
    if (b == nullptr || n == 0) {
        return;
    }
    std::string dst = enc_->encrypt(std::string(b, n));
    std::copy_n(dst.cbegin(), dst.length(), b);
}

void ServerSession::do_read_request(asio::yield_context yield) {
    auto self = shared_from_this();
    std::error_code ec;
    timer_.expires_from_now(std::chrono::seconds(4));
    std::size_t n = asio::async_read(socket_, asio::buffer(buf, enc_->getIvLen()), yield[ec]);
    if (ec) {
        return;
    }
    dec_ = getDecrypter(config_.Method, config_.Password);
    dec_->initIV(std::string(buf, enc_->getIvLen()));

    n = asio::async_read(socket_, asio::buffer(buf, 1), yield[ec]);
    if (ec) {
        destroyLater();
        return;
    }
    decrypt(buf, 1);
    bool approve = true;
    auto raddr = socket_.remote_endpoint().address().to_string();
    auto atyp = buf[0];
    std::string name, port;
    char *address = buf + 128;
    std::size_t hostlen;
    switch (atyp) {
    default:
        approve = false;
        info("incorrect header from %s", raddr.c_str());
        break;
    case typeIPv4:
        n = asio::async_read(socket_, asio::buffer(buf, lenIPv4+lenPort), yield[ec]);
        if (ec) {
            return;
        }
        decrypt(buf, n);
        if (::inet_ntop(AF_INET, reinterpret_cast<void *>(buf), address,
                        1024) == nullptr) {
            return;
        }
        name = address;
        port = std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + 4)));
    case typeIPv6:
        n = asio::async_read(socket_, asio::buffer(buf, lenIPv6+lenPort), yield[ec]);
        if (ec) {
            return;
        }
        decrypt(buf, n);
        if (::inet_ntop(AF_INET6, reinterpret_cast<void *>(buf), address,
                        1024) == nullptr) {
            return;
        }
        name = address;
        port = std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + 16)));
    case typeDm:
        n = asio::async_read(socket_, asio::buffer(buf, 1), yield[ec]);
        if (ec) {
            return;
        }
        decrypt(buf, n);
        hostlen = int(buf[0]);
        n = asio::async_read(socket_, asio::buffer(buf, hostlen+2), yield[ec]);
        if (ec) {
            return;
        }
        decrypt(buf, n);
        name = std::string(buf, n - 2);
        port = std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + n - 2)));
    }
    if (config_.AutoBan) {
        if (approve) {
            auto it = EvilIPAddresses.find(raddr);
            if (it != EvilIPAddresses.end()) {
                EvilIPAddresses.erase(raddr);
            }
        } else {
            if (++EvilIPAddresses[raddr] > 8) {
                EvilIPAddresses.erase(raddr);
                ForbiddenIPAddresses.insert(raddr);
            }
        }
    }

    do_establish(yield, name, port);
}

void ServerSession::do_establish(asio::yield_context yield, const std::string &name, const std::string &port) {
    info("connect %s:%s", name.c_str(), port.c_str());
    auto self = shared_from_this();
    std::error_code ec;
    asio::ip::tcp::resolver::query query(name, port);
    asio::ip::tcp::resolver::iterator iterator = resolver_.async_resolve(query, yield[ec]);
    if (ec) {
        return;
    }
    rsocket_.async_connect(*iterator, yield[ec]);
    if (ec) {
        return;
    }
    destroyLater_ = false;
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        do_pipe1(yield);
    });
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        do_write_iv(yield);
    });
}

void ServerSession::do_write_iv(asio::yield_context yield) {
    auto self = shared_from_this();
    auto ivlen = enc_->getIvLen();
    std::error_code ec;
    auto n = rsocket_.async_read_some(asio::buffer(rbuf+ivlen, sizeof(rbuf)-ivlen), yield[ec]);
    if (ec) {
        socket_.cancel(ec);
        return;
    }
    encrypt(rbuf+ivlen, n);
    auto iv = enc_->getIV();
    std::copy_n(iv.begin(), iv.length(), std::begin(rbuf));
    asio::async_write(socket_, asio::buffer(rbuf, ivlen+n), yield[ec]);
    if (ec) {
        socket_.cancel(ec);
        return;
    }
    do_pipe2(yield);
}

void ServerSession::do_pipe1(asio::yield_context yield) {
    auto self = shared_from_this();
    std::error_code ec;
    while (1) {
        timer_.expires_from_now(std::chrono::seconds(4));
        std::size_t n = socket_.async_read_some(asio::buffer(buf, sizeof(buf)), yield[ec]);
        if (ec) {
            rsocket_.cancel(ec);
            return;
        }
        decrypt(buf, n);
        asio::async_write(rsocket_, asio::buffer(buf, n), yield[ec]);
        if (ec) {
            socket_.cancel(ec);
            return;
        }
    }
}

void ServerSession::do_pipe2(asio::yield_context yield) {
    auto self = shared_from_this();
    std::error_code ec;
    while (1) {
        timer_.expires_from_now(std::chrono::seconds(4));
        std::size_t n = rsocket_.async_read_some(asio::buffer(rbuf, sizeof(rbuf)), yield[ec]);
        if (ec) {
            socket_.cancel(ec);
            return;
        }
        encrypt(rbuf, n);
        asio::async_write(socket_, asio::buffer(rbuf, n), yield[ec]);
        if (ec) {
            rsocket_.cancel(ec);
            return;
        }
    }
}

ServerSession::~ServerSession() {
    LOG_TRACE
    if (destroyLater_) {
        plusOneSecond(service_, std::move(socket_));
    }
}
