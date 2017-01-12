//
// Created by JohnsonJohn on 2017/1/8.
//

#include "Local.h"

Local::Local(boost::asio::io_service &io_service)
    : service_(io_service), socket_(io_service),
      acceptor_(
          io_service,
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(LocalAddress), LocalPort)),
      resolver_(io_service) {}

void Local::run() {
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    doAccept();
}

void Local::doAccept() {
    auto self = shared_from_this();
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.async_accept(socket_, [this, self](boost::system::error_code ec) {
        if (!ec) {
            std::make_shared<LocalSession>(service_, std::move(socket_))->run();
            doAccept();
        }
    });
}

LocalSession::LocalSession(boost::asio::io_service &io_service, boost::asio::ip::tcp::socket &&socket) : service_(
    io_service), socket_(std::move(socket)), rsocket_(io_service) {}

void LocalSession::run() {
    doSocks5HandShakePhase1();
}

void LocalSession::doSocks5HandShakePhase1() {
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(buf, 2),
                            [this, self](boost::system::error_code ec, std::size_t length) {
                                if (ec) {
                                    return;
                                }
                                auto ver = buf[0];
                                auto nmethods = buf[1];
                                if (ver != 5) {
                                    // bad socks version
                                    return;
                                }
                                auto handler = [this, self](boost::system::error_code ec, std::size_t length) {
                                    if (ec) {
                                        return;
                                    }
                                    buf[0] = 5;
                                    buf[2] = 0;
                                    boost::asio::async_write(socket_, boost::asio::buffer(buf, 2),
                                                             [this, self](boost::system::error_code ec,
                                                                          std::size_t length) {
                                                                 if (ec) {
                                                                     return;
                                                                 }
                                                                 doSocks5HandShakePhase2();
                                                             });
                                };
                                if (nmethods > 0) {
                                    boost::asio::async_read(socket_, boost::asio::buffer(buf, nmethods), handler);
                                } else {
                                    handler(boost::system::error_code(), 0);
                                }
                            });
}

void LocalSession::doSocks5HandShakePhase2() {
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(buf, 6),
                            [this, self](boost::system::error_code ec, std::size_t length) {
                                if (!ec) {
                                    return;
                                }
                                auto ver = buf[0];
                                auto cmd = buf[1];
                                auto atyp = buf[3];
                                if (ver != 0x5 || cmd != 0x1) {
                                    return;
                                }
                                if (atyp == 0x1) {
                                    doSocks5HandleAtyp1();
                                } else if (atyp == 0x3) {
                                    doSocks5HandleAtyp3();
                                }
                            });
}

void LocalSession::doSocks5HandleAtyp1() {
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(buf + 6, 4),
                            [self, this](boost::system::error_code ec,
                                              std::size_t length) {
                                if (ec) {
                                    return;
                                }
                                char *address = buf + 128;
                                if (::inet_ntop(AF_INET,
                                                reinterpret_cast<void *>(buf + 4),
                                                address, 1024) == nullptr) {
                                    return;
                                }
                                std::string name = address;
                                std::string port = std::to_string(
                                    ntohs(*reinterpret_cast<uint16_t *>(buf + 8)));
                            });
}

void LocalSession::doSocks5HandleAtyp3() {
    auto self = shared_from_this();
    auto len = buf[4];
    boost::asio::async_read(socket_, boost::asio::buffer(buf + 6, 1 + len),
                            [self, len, this](boost::system::error_code ec,
                                              std::size_t length) {
                                if (ec) {
                                    return;
                                }
                                std::string name(buf + 5, len);
                                std::string port = std::to_string(ntohs(*reinterpret_cast<uint16_t *>(
                                    buf + 5 + len)));
                            });
}