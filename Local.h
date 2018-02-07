#ifndef SHADOWSOCKS_ASIO_LOCALSERVER_H
#define SHADOWSOCKS_ASIO_LOCALSERVER_H

#include "config.h"
#include "encrypt.h"

class LocalSession final : public std::enable_shared_from_this<LocalSession> {
public:
    LocalSession(asio::io_service &io_service, asio::ip::tcp::socket &&socket, Config &config);
    void run();
private:
    void do_establish(asio::yield_context yield, const std::string &header);
    void do_read_iv(asio::yield_context yield);
    void do_pipe1(asio::yield_context yield);
    void do_pipe2(asio::yield_context yield);
private:
    char buf[4096];
    char rbuf[4096];
    Config &config_;
    std::unique_ptr<BaseEncrypter> enc_;
    std::unique_ptr<BaseDecrypter> dec_;
    asio::io_service &service_;
    asio::io_service::strand strand_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::socket rsocket_;
    asio::ip::tcp::resolver resolver_;
};

class Local final : public std::enable_shared_from_this<Local> {
public:
    Local(asio::io_service &io_service, const Config &config);
    void run();
private:
    Config config_;
    asio::io_service &service_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::acceptor acceptor_;
    asio::ip::tcp::resolver resolver_;
};

#endif
