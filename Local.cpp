#include "Local.h"

Local::Local(asio::io_service &io_service, const Config &config)
    : config_(config), service_(io_service),
        socket_(io_service),
        acceptor_(io_service,
            asio::ip::tcp::endpoint(asio::ip::address::from_string(config.LocalAddress), config.LocalPort)),
        resolver_(io_service) {}

void Local::run() {
    auto self = shared_from_this();
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    asio::spawn(service_, [this, self](asio::yield_context yield){
        while(1) {
            std::error_code ec;
            acceptor_.async_accept(socket_, yield[ec]);
            if (ec) {
                return;
            }
            std::make_shared<LocalSession>(service_, std::move(socket_), config_)->run();
        }
    });
}

LocalSession::LocalSession(asio::io_service &io_service, asio::ip::tcp::socket &&socket, Config &config)
    : config_(config), service_(io_service), strand_(io_service),
        socket_(std::move(socket)), rsocket_(io_service), resolver_(io_service) {}

void LocalSession::run() {
    auto self = shared_from_this();
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        std::error_code ec;
        std::size_t length = asio::async_read(socket_, asio::buffer(buf, 2), yield[ec]);
        if (ec) {
            return;
        }
        auto ver = buf[0];
        auto nmethods = buf[1];
        if (ver != 0x5) {
            return;
        }
        if (nmethods > 0) {
            asio::async_read(socket_, asio::buffer(buf, nmethods), yield[ec]);
            if (ec) {
                return;
            }
        }
        buf[0] = 0x5;
        buf[1] = 0x0;
        std::size_t n = asio::async_write(socket_, asio::buffer(buf, 2), yield[ec]);
        if (ec) {
            return;
        }
        length = asio::async_read(socket_, asio::buffer(buf, 6), yield[ec]);
        if (ec) {
            return;
        }
        ver = buf[0];
        auto cmd = buf[1];
        auto atyp = buf[3];
        if (ver != 0x5 || cmd != 0x1) {
            return;
        }
        std::string address, port;
        std::string header;
        if (atyp == typeIPv4) {
            asio::async_read(socket_, asio::buffer(buf+6, lenIPv4), yield[ec]);
            if (ec) {
                return;
            }
            address = asio::ip::address_v4(
                    ntohl(*reinterpret_cast<long *>(buf + 4))).to_string();
            port = std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + 4 + lenIPv4)));
            header = std::string(buf + 3, 1 + lenIPv4 + lenPort);
        } else if (atyp == typeIPv6) {
            asio::async_read(socket_, asio::buffer(buf+6, lenIPv6), yield[ec]);
            if (ec) {
                return;
            }
            asio::ip::address_v6::bytes_type bytes;
            std::copy_n(buf + 4, bytes.size(), bytes.data());
            address = asio::ip::address_v6(bytes).to_string();
            port = std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + 4 + lenIPv6)));
            header = std::string(buf + 3, 1 + lenIPv6 + lenPort);
        } else if (atyp == typeDm) {
            auto len = reinterpret_cast<unsigned char *>(buf)[4];
            asio::async_read(socket_, asio::buffer(buf+6, 1+len), yield[ec]);
            if (ec) {
                return;
            }
            address = std::string(buf+5, len);
            port = std::to_string(ntohs(*reinterpret_cast<uint16_t *>(buf + 5 + len)));
            header = std::string(buf + 3, len + 4);
        }
        info("connect %s:%s", address.c_str(), port.c_str());
        do_establish(yield, header);
    });
}

void LocalSession::do_establish(asio::yield_context yield, const std::string &header) {
    if (header.empty()) {
        return;
    }
    auto self = shared_from_this();
    enc_ = getEncrypter(config_.Method, config_.Password);
    auto iv = enc_->getIV();
    auto ivlen = enc_->getIvLen();
    auto encHeader = enc_->encrypt(header);
    std::copy_n(iv.begin(), ivlen, std::begin(buf));
    std::copy_n(encHeader.begin(), encHeader.length(), std::begin(buf) + ivlen);
    ivlen += encHeader.length();
    asio::ip::tcp::resolver::query query(config_.ServerAddress, std::to_string(config_.ServerPort));
    std::error_code ec;
    asio::ip::tcp::resolver::iterator iterator = resolver_.async_resolve(query, yield[ec]);
    if (ec) {
        return;
    }
    rsocket_.async_connect(*iterator, yield[ec]);
    if (ec) {
        return;
    }
    rbuf[0] = 0x5;
    rbuf[1] = 0x0;
    rbuf[2] = 0x0;
    std::copy_n(header.begin(), header.length(), std::begin(rbuf) + 3);
    std::size_t length = asio::async_write(socket_, asio::buffer(rbuf, 3+header.length()), yield[ec]);
    if (ec) {
        return;
    }
    asio::async_write(rsocket_, asio::buffer(buf, ivlen), yield[ec]);
    if (ec) {
        return;
    }
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        do_read_iv(yield);
    });
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        do_pipe2(yield);
    });
}

void LocalSession::do_read_iv(asio::yield_context yield) {
    auto self = shared_from_this();
    dec_ = getDecrypter(config_.Method, config_.Password);
    std::error_code ec;
    std::size_t n = asio::async_read(rsocket_, asio::buffer(rbuf, enc_->getIvLen()), yield[ec]);
    if (ec) {
        socket_.cancel(ec);
        return;
    }
    dec_->initIV(std::string(rbuf, n));
    do_pipe1(yield);
}

void LocalSession::do_pipe1(asio::yield_context yield) {
    auto self = shared_from_this();
    while(1) {
        std::error_code ec;
        std::size_t n = rsocket_.async_read_some(asio::buffer(rbuf, 4096), yield[ec]);
        if (ec) {
            socket_.cancel(ec);
            return;
        }
        std::string dst = dec_->decrypt(std::string(rbuf, n));
        std::copy_n(dst.cbegin(), dst.length(), std::begin(rbuf));
        asio::async_write(socket_, asio::buffer(rbuf, n), yield[ec]);
        if (ec) {
            rsocket_.cancel(ec);
            return;
        }
    }
}

void LocalSession::do_pipe2(asio::yield_context yield) {
    auto self = shared_from_this();
    while(1) {
        std::error_code ec;
        std::size_t n = socket_.async_read_some(asio::buffer(buf, 4096), yield[ec]);
        if (ec) {
            rsocket_.cancel(ec);
            return;
        }
        std::string dst = enc_->encrypt(std::string(buf, n));
        std::copy_n(dst.cbegin(), dst.length(), buf);
        asio::async_write(rsocket_, asio::buffer(buf, n), yield[ec]);
        if (ec) {
            socket_.cancel(ec);
            return;
        }
    }
}
