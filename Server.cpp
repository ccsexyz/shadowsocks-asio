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
        if (ok) {
            std::make_shared<ServerSession>(service_, std::move(socket_), config_)
                ->run();
        } else {
            plusOneSecond(service_, std::move(socket_));
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

void ServerSession::destroyLater() {
    plusOneSecond(service_, std::move(socket_));
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

void ServerSession::doReadIV() {
    auto self = shared_from_this();
    async_read_with_timeout(enc_->getIvLen(), boost::posix_time::seconds(4),
                            [this, self](boost::system::error_code ec, std::size_t length) {
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
    async_read_with_timeout_1(1, boost::posix_time::seconds(1),
                              [this, self](boost::system::error_code ec, std::size_t length) {
                                  if (ec) {
                                      destroyLater();
                                      return;
                                  }
                                  bool approve = true;
                                  auto address = socket_.remote_endpoint().address().to_string();
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
                                      default:
                                          approve = false;
                                          BOOST_LOG_TRIVIAL(info) << "bad header from " << address;
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
    async_read_with_timeout_1(lenIPv6, boost::posix_time::seconds(1), [this, self](boost::system::error_code ec,
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
    async_read_with_timeout_1(1, boost::posix_time::seconds(1),
                              [this, self](boost::system::error_code ec, std::size_t length) {
                                  if (ec) {
                                      return;
                                  }
                                  LOG_TRACE
                                  std::cout << (unsigned char) buf[0] + 2 << std::endl;
                                  async_read_with_timeout_1((unsigned char) buf[0] + 2, boost::posix_time::seconds(1),
                                                            [this, self](boost::system::error_code ec,
                                                                         std::size_t length) {
                                                                if (ec || length < 2) {
                                                                    return;
                                                                }
                                                                std::string name(buf, length - 2);
                                                                std::string port = std::to_string(
                                                                    ntohs(*reinterpret_cast<uint16_t *>(buf + length -
                                                                                                        2)));
                                                                LOG_TRACE
                                                                doEstablish(name, port);
                                                            });
                              });
}

void ServerSession::doEstablish(std::string name, std::string port) {
    BOOST_LOG_TRIVIAL(info) << "connect " << name << ":" << port;
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
                    destroyLater_ = false;
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
//                std::cout << ec << std::endl;
                rsocket_.cancel(ec);
                return;
            }
            LOG_TRACE
            // std::cout << std::string(buf, length) << std::endl;
            boost::asio::async_write(
                rsocket_, boost::asio::buffer(buf, length),
                [this, self](boost::system::error_code ec, std::size_t length) {
                    if (ec) {
                        LOG_TRACE
//                        std::cout << ec << std::endl;
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
        boost::asio::buffer(rbuf, 16384),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (ec) {
                LOG_TRACE
//                std::cout << ec << std::endl;
                socket_.cancel(ec);
                return;
            }
            LOG_TRACE
            // std::cout << std::string(rbuf, length) << std::endl;
            async_write(length, [this, self](boost::system::error_code ec,
                                             std::size_t length) {
                if (ec) {
                    LOG_TRACE
//                    std::cout << ec << std::endl;
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

void ServerSession::async_read_with_timeout(std::size_t length, boost::posix_time::time_duration td, Handler handler) {
    std::weak_ptr<ServerSession> wss(shared_from_this());
    auto dt = std::make_shared<boost::asio::deadline_timer>(service_, td);
    dt->async_wait([dt, wss, this](const boost::system::error_code &ec) {
        if (!wss.expired()) {
            boost::system::error_code errc = ec;
            socket_.cancel(errc);
        }
    });
    boost::asio::async_read(socket_, boost::asio::buffer(buf, length),
                            [handler, this, dt](boost::system::error_code ec, std::size_t length) {
                                if (!ec) {
                                    dt->cancel();
                                }
                                handler(ec, length);
                            });
}

void
ServerSession::async_read_with_timeout_1(std::size_t length, boost::posix_time::time_duration td, Handler handler) {
    async_read_with_timeout(length, td, [handler, this](boost::system::error_code ec, std::size_t length) {
        if (!ec) {
            std::string dst = dec_->decrypt(std::string(buf, length));
            std::copy_n(dst.cbegin(), dst.length(), std::begin(buf));
        }
        handler(ec, length);
    });
}
