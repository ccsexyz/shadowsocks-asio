#include "Server.h"

Server::Server(boost::asio::io_service &io_service, const Config &config)
    : config_(config), service_(io_service), socket_(io_service),
      acceptor_(io_service,
                boost::asio::ip::tcp::endpoint(
                    boost::asio::ip::address::from_string(config.ServerAddress),
                    config.ServerPort)) {}

void Server::run() {
#ifdef __linux__
    if(config_.IsFastOpen) {
        auto fd = acceptor_.native_handle();
        int qlen = 5;
        ::setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
    }
#endif
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    doAccept();
}

void Server::doAccept() {
    auto self = shared_from_this();
    acceptor_.async_accept(socket_, [this, self](boost::system::error_code ec) {
        if (ec) {
            return;
        }
        auto endpoint = socket_.remote_endpoint();
        auto address = endpoint.address().to_string();
        bool ok = checkAddress(address);
        if(ok) {
            std::make_shared<ServerSession>(service_, std::move(socket_), config_)
                ->run();
        } else {
            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(std::move(socket_));
            runAfter(service_, boost::posix_time::seconds(4 + getRandomNumber() % 20), [socket]{

            });
        }
        doAccept();
    });
}

ServerSession::ServerSession(boost::asio::io_service &io_service,
                             boost::asio::ip::tcp::socket &&socket,
                             Config &config)
    : config_(config), service_(io_service), socket_(std::move(socket)), rsocket_(io_service),
      resolver_(io_service) {}

void ServerSession::run() {
    enc_ = getEncrypter(config_.Method, config_.Password);
    doReadIV();
}

void ServerSession::doReadIV() {
    auto self = shared_from_this();
    boost::asio::async_read(
        socket_, boost::asio::buffer(buf, enc_->getIvLen()),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (ec) {
                return;
            }
            dec_ = getDecrypter(config_.Method, config_.Password);
            dec_->initIV(std::string(buf, enc_->getIvLen()));
            doGetRequest();
        });
}

void ServerSession::async_read_some(Handler handler) {
    socket_.async_read_some(
        boost::asio::buffer(buf, 4096),
        [this, handler](boost::system::error_code ec, std::size_t length) {
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
    boost::asio::async_read(
        socket_, boost::asio::buffer(buffer, len),
        [this, handler, buffer](boost::system::error_code ec,
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
    boost::asio::async_write(
        socket_, boost::asio::buffer(buffer, len),
        [this, handler, buffer](boost::system::error_code ec,
                                std::size_t length) { handler(ec, length); });
}

void ServerSession::async_write(std::size_t len, Handler handler) {
    async_write(rbuf, len, handler);
}

void ServerSession::doGetRequest() {
    auto self = shared_from_this();
    async_read(1,
               [this, self](boost::system::error_code ec, std::size_t length) {
                   if (ec) {
                       return;
                   }
                   switch (buf[0] & AddrMask) {
                       case typeIPv4:
                           doGetIPv4Request();
                           break;
                       case typeIPv6:
                           doGetIPv6Request();
                           break;
                       case typeDm:
                           doGetDmRequest();
                           break;
                   }
               });
}

void ServerSession::doGetIPv4Request() {
    auto self = shared_from_this();
    async_read(lenIPv4, [this, self](boost::system::error_code ec,
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
    async_read(lenIPv6, [this, self](boost::system::error_code ec,
                                     std::size_t length) {
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
    async_read(
        1, [this, self](boost::system::error_code ec, std::size_t length) {
            if (ec) {
                return;
            }
            LOG_TRACE
            std::cout << (unsigned char) buf[0] + 2 << std::endl;
            async_read(
                (unsigned char) buf[0] + 2,
                [this, self](boost::system::error_code ec, std::size_t length) {
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
    std::cout << name << ":" << port << std::endl;
    LOG_TRACE
    auto self = shared_from_this();
    boost::asio::ip::tcp::resolver::query query(name, port);
    resolver_.async_resolve(
        query, [this, self](boost::system::error_code ec,
                            boost::asio::ip::tcp::resolver::iterator iterator) {
            if (ec) {
                return;
            }
            rsocket_.async_connect(
                *iterator, [this, self](boost::system::error_code ec) {
                    LOG_TRACE
                    if (ec) {
                        return;
                    }
                    auto iv = enc_->getIV();
                    std::copy(iv.begin(), iv.end(), std::begin(buf));
                    boost::asio::async_write(
                        socket_, boost::asio::buffer(buf, iv.length()),
                        [this, self](boost::system::error_code ec,
                                     std::size_t length) {
                            LOG_TRACE
                            if (ec) {
                                return;
                            }
                            doPipe1();
                            doPipe2();
                        });
                });
        });
}

void ServerSession::doPipe1() {
    LOG_TRACE
    auto self = shared_from_this();
    async_read_some(
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (ec) {
                LOG_TRACE
                std::cout << ec << std::endl;
                // rsocket_.close();
                return;
            }
            LOG_TRACE
            // std::cout << std::string(buf, length) << std::endl;
            boost::asio::async_write(
                rsocket_, boost::asio::buffer(buf, length),
                [this, self](boost::system::error_code ec, std::size_t length) {
                    if (ec) {
                        LOG_TRACE
                        std::cout << ec << std::endl;
                        // socket_.close();
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
        boost::asio::buffer(rbuf, 16384),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (ec) {
                LOG_TRACE
                std::cout << ec << std::endl;
                // socket_.close();
                return;
            }
            LOG_TRACE
            // std::cout << std::string(rbuf, length) << std::endl;
            async_write(length, [this, self](boost::system::error_code ec,
                                             std::size_t length) {
                if (ec) {
                    LOG_TRACE
                    std::cout << ec << std::endl;
                    // rsocket_.close();
                    return;
                }
                doPipe2();
            });
        });
}

ServerSession::~ServerSession() { LOG_TRACE }
