//
// Created by JohnsonJohn on 2017/1/9.
//

#ifndef SHADOWSOCKS_ASIO_SERVER_H
#define SHADOWSOCKS_ASIO_SERVER_H

#include "config.h"
#include "encrypt.h"

using Handler = std::function<void(boost::system::error_code, std::size_t)>;

class ServerSession final : public std::enable_shared_from_this<ServerSession> {
public:
    ServerSession(boost::asio::io_service &io_service,
                  boost::asio::ip::tcp::socket &&socket, Config &config);
    ~ServerSession();
    void run();

private:
    void async_read_some(Handler handler);
    void async_read(std::size_t len, Handler handler);
    void async_read(char *buffer, std::size_t len, Handler handler);
    void async_write(std::size_t len, Handler handler);
    void async_write(char *buffer, std::size_t len, Handler handler);

private:
    void doReadIV();
    void doGetRequest();
    void doGetIPv4Request();
    void doGetIPv6Request();
    void doGetDmRequest();
    void doEstablish(std::string name, std::string port);
    void doPipe1();
    void doPipe2();

private:
    char buf[4096];
    char rbuf[16384];
    Config &config_;
    std::unique_ptr<BaseEncrypter> enc_;
    std::unique_ptr<BaseDecrypter> dec_;
    boost::asio::io_service &service_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::socket rsocket_;
    boost::asio::ip::tcp::resolver resolver_;
};

class Server final : public std::enable_shared_from_this<Server> {
public:
    Server(boost::asio::io_service &io_service, const Config &config);
    void run();

private:
    void doAccept();

private:
    Config config_;
    boost::asio::io_service &service_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::acceptor acceptor_;
};

#endif // SHADOWSOCKS_ASIO_SERVER_H