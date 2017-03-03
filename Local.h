#ifndef SHADOWSOCKS_ASIO_LOCALSERVER_H
#define SHADOWSOCKS_ASIO_LOCALSERVER_H

#include "config.h"
#include "encrypt.h"

class LocalSession final : public std::enable_shared_from_this<LocalSession> {
public:
    LocalSession(asio::io_service &io_service,
                 asio::ip::tcp::socket &&socket, Config &config);
    void run();

private:
    void async_read_some(Handler handler);
    void async_read(std::size_t len, Handler handler);
    void async_read(char *buffer, std::size_t len, Handler handler);
    void async_write(std::size_t len, Handler handler);
    void async_write(char *buffer, std::size_t len, Handler handler);

private:
    void doSocks5HandShakePhase1();
    void doSocks5HandShakePhase2();
    void doSocks5HandleIPv4();
    void doSocks5HandleIPv6();
    void doSocks5HandleDm();
    void doEstablish(const std::string &header);
    void doReadIV();
    void doPipe1();
    void doPipe2();

private:
    char buf[4096];
    char rbuf[16384];
    Config &config_;
    std::unique_ptr<BaseEncrypter> enc_;
    std::unique_ptr<BaseDecrypter> dec_;
    asio::io_service &service_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::socket rsocket_;
    asio::ip::tcp::resolver resolver_;
};

class Local final : public std::enable_shared_from_this<Local> {
public:
    Local(asio::io_service &io_service, const Config &config);
    void run();

private:
    void doAccept();

private:
    Config config_;
    asio::io_service &service_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::acceptor acceptor_;
    asio::ip::tcp::resolver resolver_;
};

#endif // SHADOWSOCKS_ASIO_LOCALSERVER_H
