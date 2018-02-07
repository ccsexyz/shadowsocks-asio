#ifndef SHADOWSOCKS_ASIO_SERVER_H
#define SHADOWSOCKS_ASIO_SERVER_H

#include "config.h"
#include "encrypt.h"

class ServerSession final : public std::enable_shared_from_this<ServerSession> {
public:
    ServerSession(asio::io_service &io_service,
                  asio::ip::tcp::socket &&socket, Config &config);
    ~ServerSession();
    void run();

private:
    void destroyLater();
    void decrypt(char *b, std::size_t n);
    void encrypt(char *b, std::size_t n);
    void do_read_request(asio::yield_context yield);
    void do_establish(asio::yield_context yield, const std::string &name, const std::string &port);
    void do_write_iv(asio::yield_context yield);
    void do_pipe1(asio::yield_context yield);
    void do_pipe2(asio::yield_context yield);

private:
    bool destroyLater_ = true;
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
    asio::high_resolution_timer timer_;
};

class Server final : public std::enable_shared_from_this<Server> {
public:
    Server(asio::io_service &io_service, const Config &config);
    void run();

private:
    Config config_;
    asio::io_service &service_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::acceptor acceptor_;
    asio::ip::tcp::resolver resolver_;
};

#endif // SHADOWSOCKS_ASIO_SERVER_H
