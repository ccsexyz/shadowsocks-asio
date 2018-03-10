#include "Server.h"

Server::Server(asio::io_service &io_service, const Config &config)
    : config_(config), service_(io_service), socket_(io_service),
      acceptor_(io_service,
                asio::ip::tcp::endpoint(
                    asio::ip::address::from_string(config.ServerAddress),
                    config.ServerPort)),
      resolver_(io_service) {}

void Server::run() {
#ifdef __linux__
    if (config_.IsFastOpen) {
        auto fd = acceptor_.native_handle();
        int qlen = 5;
        ::setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
    }
#endif
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    doAccept();
}

void Server::doAccept() {
    auto self = shared_from_this();
    acceptor_.async_accept(socket_, [this, self](std::error_code ec) {
        if (ec) {
            return;
        }
        auto endpoint = socket_.remote_endpoint();
        auto address = endpoint.address().to_string();
        bool ok = checkAddress(address);
        if (ok) {
            std::make_shared<ServerSession>(service_, std::move(socket_),
                                            config_)
                ->run();
        } else {
            plusOneSecond(service_, std::move(socket_));
        }
        doAccept();
    });
}

ServerSession::ServerSession(asio::io_service &io_service,
                             asio::ip::tcp::socket &&socket,
                             Config &config)
    : config_(config), service_(io_service), socket_(std::move(socket)),
      rsocket_(io_service), resolver_(io_service) {}

void ServerSession::run() {
    enc_ = getEncrypter(config_.Method, config_.Password);
    doReadIV();
}

void ServerSession::destroyLater() {
    plusOneSecond(service_, std::move(socket_));
}

void ServerSession::async_read_some(Handler handler) {
    socket_.async_read_some(
        asio::buffer(buf, 4096),
        [this, handler](std::error_code ec, std::size_t length) {
            if (!ec) {
                std::string dst = dec_->decrypt(std::string(buf, length));
                std::copy_n(dst.cbegin(), dst.length(), std::begin(buf));
            }
            handler(ec, length);
        });
}

void ServerSession::async_read(std::size_t len, Handler handler) {
    async_read(buf, len, handler);
}

void ServerSession::async_read(char *buffer, std::size_t len, Handler handler) {
    asio::async_read(
        socket_, asio::buffer(buffer, len),
        [this, handler, buffer](std::error_code ec,
                                std::size_t length) {
            if (!ec) {
                std::string dst = dec_->decrypt(std::string(buffer, length));
                std::copy_n(dst.cbegin(), dst.length(), buffer);
            }
            handler(ec, length);
        });
}

void ServerSession::async_write(char *buffer, std::size_t len,
                                Handler handler) {
    std::string dst = enc_->encrypt(std::string(buffer, len));
    std::copy_n(dst.cbegin(), dst.length(), buffer);
    asio::async_write(
        socket_, asio::buffer(buffer, len),
        [this, handler, buffer](std::error_code ec,
                                std::size_t length) { handler(ec, length); });
}

void ServerSession::async_write(std::size_t len, Handler handler) {
    async_write(rbuf, len, handler);
}

void ServerSession::doReadIV() {
    auto self = shared_from_this();
    async_read_with_timeout(
        enc_->getIvLen(), std::chrono::seconds(4),
        [this, self](std::error_code ec, std::size_t length) {
            if (ec) {
                return;
            }
            dec_ = getDecrypter(config_.Method, config_.Password);
            dec_->initIV(std::string(buf, enc_->getIvLen()));
            doGetRequest();
        });
}

void ServerSession::doGetRequest() {
    auto self = shared_from_this();
    async_read_with_timeout_1(
        1, std::chrono::seconds(1),
        [this, self](std::error_code ec, std::size_t length) {
            if (ec) {
                destroyLater();
                return;
            }
            bool approve = true;
            auto address = socket_.remote_endpoint().address().to_string();
            switch (buf[0]) {
            case typeIPv4:
                doGetIPv4Request();
                break;
            case typeIPv6:
                doGetIPv6Request();
                break;
            case typeDm:
                doGetDmRequest();
                break;
            default:
                approve = false;
                LOG(INFO) << "incorrect header from " << address;
                break;
            }
            if (config_.AutoBan == false) {
                return;
            }
            if (approve) {
                auto it = EvilIPAddresses.find(address);
                if (it != EvilIPAddresses.end()) {
                    EvilIPAddresses.erase(address);
                }
            } else {
                if (++EvilIPAddresses[address] > 8) {
                    EvilIPAddresses.erase(address);
                    ForbiddenIPAddresses.insert(address);
                }
            }
        });
}

void ServerSession::doGetIPv4Request() {
    auto self = shared_from_this();
    async_read(lenIPv4 + lenPort, [this, self](std::error_code ec,
                                               std::size_t length) {
        if (ec) {
            return;
        }
        char *address = buf + 128;
        if (::inet_ntop(AF_INET, reinterpret_cast<void *>(buf), address,
                        1024) == nullptr) {
            return;
        }
        std::string name = address;
        std::string port =
            std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + 4)));
        doEstablish(name, port);
    });
}

void ServerSession::doGetIPv6Request() {
    auto self = shared_from_this();
    async_read_with_timeout_1(
        lenIPv6 + lenPort, std::chrono::seconds(1),
        [this, self](std::error_code ec, std::size_t length) {
            if (ec) {
                return;
            }
            char *address = buf + 128;
            if (::inet_ntop(AF_INET6, reinterpret_cast<void *>(buf), address,
                            1024) == nullptr) {
                return;
            }
            std::string name = address;
            std::string port =
                std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + 16)));
            doEstablish(name, port);
        });
}

void ServerSession::doGetDmRequest() {
    LOG_TRACE
    auto self = shared_from_this();
    async_read_with_timeout_1(
        1, std::chrono::seconds(1),
        [this, self](std::error_code ec, std::size_t length) {
            if (ec) {
                return;
            }
            LOG_TRACE
            std::cout << (unsigned char)buf[0] + 2 << std::endl;
            async_read_with_timeout_1(
                (unsigned char)buf[0] + 2, std::chrono::seconds(1),
                [this, self](std::error_code ec, std::size_t length) {
                    if (ec || length < 2) {
                        return;
                    }
                    std::string name(buf, length - 2);
                    std::string port = std::to_string(
                        ntohs(*reinterpret_cast<uint16_t *>(buf + length - 2)));
                    LOG_TRACE
                    doEstablish(name, port);
                });
        });
}

void ServerSession::doEstablish(std::string name, std::string port) {
    LOG(INFO) << "connect " << name << ":" << port;
    LOG_TRACE
    auto self = shared_from_this();
    asio::ip::tcp::resolver::query query(name, port);
    resolver_.async_resolve(
        query, [this, self](std::error_code ec,
                            asio::ip::tcp::resolver::iterator iterator) {
            if (ec) {
                return;
            }
            rsocket_.async_connect(*iterator,
                                   [this, self](std::error_code ec) {
                                       LOG_TRACE
                                       if (ec) {
                                           return;
                                       }
                                       destroyLater_ = false;
                                       doPipe1();
                                       doWriteIV();
                                   });
        });
}

void ServerSession::doWriteIV() {
    auto self = shared_from_this();
    auto ivlen = enc_->getIvLen();
    rsocket_.async_read_some(
        asio::buffer(rbuf, sizeof(rbuf) - ivlen),
        [this, self](std::error_code ec, std::size_t length) {
            if (ec) {
                socket_.cancel(ec);
                return;
            }
            auto dst = enc_->encrypt(std::string(rbuf, length));
            auto iv = enc_->getIV();
            std::copy_n(iv.begin(), iv.length(), std::begin(rbuf));
            std::copy_n(dst.begin(), dst.length(),
                        std::begin(rbuf) + iv.length());
            asio::async_write(
                socket_, asio::buffer(rbuf, iv.length() + dst.length()),
                [this, self](std::error_code ec, std::size_t length) {
                    if (ec) {
                        rsocket_.cancel(ec);
                        return;
                    }
                    doPipe2();
                });
        });
}

void ServerSession::doPipe1() {
    LOG_TRACE
    auto self = shared_from_this();
    async_read_some(
        [this, self](std::error_code ec, std::size_t length) {
            if (ec) {
                LOG_TRACE
                rsocket_.cancel(ec);
                return;
            }
            LOG_TRACE
            asio::async_write(
                rsocket_, asio::buffer(buf, length),
                [this, self](std::error_code ec, std::size_t length) {
                    if (ec) {
                        LOG_TRACE
                        socket_.cancel(ec);
                        return;
                    }
                    doPipe1();
                });
        });
}

void ServerSession::doPipe2() {
    LOG_TRACE
    auto self = shared_from_this();
    rsocket_.async_read_some(
        asio::buffer(rbuf, 16384),
        [this, self](std::error_code ec, std::size_t length) {
            if (ec) {
                LOG_TRACE
                socket_.cancel(ec);
                return;
            }
            LOG_TRACE
            async_write(length, [this, self](std::error_code ec,
                                             std::size_t length) {
                if (ec) {
                    LOG_TRACE
                    rsocket_.cancel(ec);
                    return;
                }
                doPipe2();
            });
        });
}

ServerSession::~ServerSession() {
    LOG_TRACE
    if (destroyLater_) {
        plusOneSecond(service_, std::move(socket_));
    }
}

void ServerSession::async_read_with_timeout(std::size_t length,
                                            asio::high_resolution_timer::duration td,
                                            Handler handler) {
    std::weak_ptr<ServerSession> wss(shared_from_this());
    auto dt = std::make_shared<asio::high_resolution_timer>(service_, td);
    dt->async_wait([dt, wss, this](const std::error_code &ec) {
        if (!wss.expired()) {
            std::error_code errc = ec;
            socket_.cancel(errc);
        }
    });
    asio::async_read(
        socket_, asio::buffer(buf, length),
        [handler, this, dt](std::error_code ec, std::size_t length) {
            if (!ec) {
                dt->cancel();
            }
            handler(ec, length);
        });
}

void ServerSession::async_read_with_timeout_1(
    std::size_t length, asio::high_resolution_timer::duration td, Handler handler) {
    async_read_with_timeout(
        length, td,
        [handler, this](std::error_code ec, std::size_t length) {
            if (!ec) {
                std::string dst = dec_->decrypt(std::string(buf, length));
                std::copy_n(dst.cbegin(), dst.length(), std::begin(buf));
            }
            handler(ec, length);
        });
}
