#include "Local.h"

Local::Local(asio::io_service &io_service, const Config &config)
        : config_(config), service_(io_service), socket_(io_service),
          acceptor_(io_service,
                  asio::ip::tcp::endpoint(
                          asio::ip::address::from_string(config.LocalAddress),
                          config.LocalPort)),
          resolver_(io_service) {}

void Local::run() {
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

void Local::doAccept() {
    auto self = shared_from_this();
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.async_accept(socket_, [this, self](std::error_code ec) {
        if (ec) {
            return;
        }
        std::make_shared<LocalSession>(service_, std::move(socket_), config_)
                ->run();
        doAccept();
    });
}

LocalSession::LocalSession(asio::io_service &io_service,
                           asio::ip::tcp::socket &&socket,
                           Config &config)
        : config_(config), service_(io_service), socket_(std::move(socket)),
          rsocket_(io_service), resolver_(io_service) {}

void LocalSession::run() { doSocks5HandShakePhase1(); }

void LocalSession::doSocks5HandShakePhase1() {
    auto self = shared_from_this();
    asio::async_read(
            socket_, asio::buffer(buf, 2),
            [this, self](std::error_code ec, std::size_t length) {
                if (ec) {
                    return;
                }
                auto ver = buf[0];
                auto nmethods = buf[1];
                if (ver != 5) {
                    // bad socks version
                    return;
                }
                auto handler = [this, self](std::error_code ec,
                                            std::size_t length) {
                    if (ec) {
                        return;
                    }
                    buf[0] = 5;
                    buf[1] = 0;
                    asio::async_write(
                            socket_, asio::buffer(buf, 2),
                            [this, self](std::error_code ec,
                                         std::size_t length) {
                                if (ec) {
                                    return;
                                }
                                doSocks5HandShakePhase2();
                            });
                };
                if (nmethods > 0) {
                    asio::async_read(
                            socket_, asio::buffer(buf, nmethods), handler);
                } else {
                    handler(std::error_code(), 0);
                }
            });
}

void LocalSession::doSocks5HandShakePhase2() {
    auto self = shared_from_this();
    asio::async_read(
            socket_, asio::buffer(buf, 6),
            [this, self](std::error_code ec, std::size_t length) {
                if (ec) {
                    return;
                }
                auto ver = buf[0];
                auto cmd = buf[1];
                auto atyp = buf[3];
                if (ver != 0x5 || cmd != 0x1) {
                    return;
                }
                if (atyp == typeIPv4) {
                    doSocks5HandleIPv4();
                } else if (atyp == typeIPv6) {
                    doSocks5HandleIPv6();
                } else if (atyp == typeDm) {
                    doSocks5HandleDm();
                }
            });
}

void LocalSession::doSocks5HandleIPv4() {
    auto self = shared_from_this();
    asio::async_read(
            socket_, asio::buffer(buf + 6, lenIPv4),
            [self, this](std::error_code ec, std::size_t length) {
                if (ec) {
                    return;
                }
                auto address = asio::ip::address_v4(
                        ntohl(*reinterpret_cast<long *>(buf + 4)));
                auto port = ntohs(*reinterpret_cast<uint16_t *>(buf + 4 + lenIPv4));
                auto header = std::string(buf + 3, 1 + lenIPv4 + lenPort);
                LOG(INFO) << "connect " << address.to_string() << ":" << port;
                doEstablish(header);
            });
}

void LocalSession::doSocks5HandleIPv6() {
    auto self = shared_from_this();
    asio::async_read(
            socket_, asio::buffer(buf + 6, lenIPv6),
            [self, this](std::error_code ec, std::size_t length) {
                if (ec) {
                    return;
                }
                asio::ip::address_v6::bytes_type bytes;
                std::copy_n(buf + 4, bytes.size(), bytes.data());
                auto address = asio::ip::address_v6(bytes);
                auto port = ntohs(*reinterpret_cast<uint16_t *>(buf + 4 + lenIPv6));
                auto header = std::string(buf + 3, 1 + lenIPv6 + lenPort);
                LOG(INFO) << "connect " << address.to_string() << ":" << port;
                doEstablish(header);
            });
}

void LocalSession::doSocks5HandleDm() {
    auto self = shared_from_this();
    auto len = reinterpret_cast<unsigned char *>(buf)[4];
    asio::async_read(
            socket_, asio::buffer(buf + 6, 1 + len),
            [self, len, this](std::error_code ec, std::size_t length) {
                if (ec) {
                    return;
                }
                std::string address(buf + 5, len);
                auto port = ntohs(*reinterpret_cast<uint16_t *>(buf + 5 + len));
                auto header = std::string(buf + 3, len + 4);
                LOG(INFO) << "connect " << address << ":" << port;
                doEstablish(header);
            });
}

void LocalSession::doEstablish(const std::string &header) {
    if (header.empty()) {
        return;
    }
    enc_ = getEncrypter(config_.Method, config_.Password);
    auto iv = enc_->getIV();
    auto ivlen = enc_->getIvLen();
    std::copy_n(iv.begin(), ivlen, std::begin(buf));
    auto hdrsz = header.size();
    enc_->encrypt(header.data(), hdrsz, buf+ivlen, hdrsz);
    ivlen += hdrsz;
    auto self = shared_from_this();
    asio::ip::tcp::resolver::query query(config_.ServerAddress, std::to_string(config_.ServerPort));
    resolver_.async_resolve(query,
            [this, self, ivlen, header](std::error_code ec, asio::ip::tcp::resolver::iterator iterator) {
                if (ec) {
                    return;
                }
                rsocket_.async_connect(
                        *iterator,
                        [this, self, ivlen, header](std::error_code ec) {
                            if (ec) {
                                return;
                            }
                            rbuf[0] = 0x5;
                            rbuf[1] = 0x0;
                            rbuf[2] = 0x0;
                            std::copy_n(header.begin(), header.length(), std::begin(rbuf) + 3);
                            asio::async_write(
                                    socket_, asio::buffer(rbuf, 3 + header.length()),
                                    [this, self, ivlen](std::error_code ec,
                                                        std::size_t length) {
                                        if (ec) {
                                            return;
                                        }
                                        asio::async_write(
                                                rsocket_, asio::buffer(buf, ivlen),
                                                [this, self](std::error_code ec,
                                                             std::size_t length) {
                                                    if (ec) {
                                                        return;
                                                    }
                                                    doReadIV();
                                                    doPipe2();
                                                });
                                    });
                        });
            });
}

void LocalSession::async_read_some(Handler handler) {
    rsocket_.async_read_some(
            asio::buffer(rbuf, 4096),
            [this, handler](std::error_code ec, std::size_t length) {
                if (!ec) {
                    dec_->decrypt(rbuf, length, rbuf, length);
                }
                handler(ec, length);
            });
}

void LocalSession::async_read(size_t len, Handler handler) {
    async_read(rbuf, len, handler);
}

void LocalSession::async_read(char *buffer, size_t len, Handler handler) {
    asio::async_read(
            rsocket_, asio::buffer(buffer, len),
            [this, handler, buffer](std::error_code ec,
                                    std::size_t length) {
                if (!ec) {
                    dec_->decrypt(buffer, length, buffer, length);
                }
                handler(ec, length);
            });
}

void LocalSession::async_write(size_t len, Handler handler) {
    async_write(buf, len, handler);
}

void LocalSession::async_write(char *buffer, size_t len, Handler handler) {
    enc_->encrypt(buffer, len, buffer, len);
    asio::async_write(
            rsocket_, asio::buffer(buffer, len),
            [this, handler, buffer](std::error_code ec,
                                    std::size_t length) { handler(ec, length); });
}

void LocalSession::doPipe1() {
    auto self = shared_from_this();
    async_read_some(
            [this, self](std::error_code ec, std::size_t length) {
                if (ec) {
                    socket_.cancel(ec);
                    return;
                }
                asio::async_write(
                        socket_, asio::buffer(rbuf, length),
                        [this, self](std::error_code ec, std::size_t length) {
                            if (ec) {
                                rsocket_.cancel(ec);
                                return;
                            }
                            doPipe1();
                        });
            });
}

void LocalSession::doPipe2() {
    auto self = shared_from_this();
    socket_.async_read_some(
            asio::buffer(buf, 4096),
            [this, self](std::error_code ec, std::size_t length) {
                if (ec) {
                    rsocket_.cancel(ec);
                    return;
                }
                async_write(length, [this, self](std::error_code ec,
                                                 std::size_t length) {
                    if (ec) {
                        socket_.cancel(ec);
                        return;
                    }
                    doPipe2();
                });
            });
}

void LocalSession::doReadIV() {
    auto self = shared_from_this();
    dec_ = getDecrypter(config_.Method, config_.Password);
    asio::async_read(
            rsocket_, asio::buffer(rbuf, enc_->getIvLen()),
            [this, self](std::error_code ec, std::size_t length) {
                if (ec) {
                    socket_.cancel(ec);
                    return;
                }
                dec_->initIV(std::string(rbuf, length));
                doPipe1();
            });
}
