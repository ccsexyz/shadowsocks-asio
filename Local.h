#ifndef SHADOWSOCKS_ASIO_LOCALSERVER_H
#define SHADOWSOCKS_ASIO_LOCALSERVER_H

#include "config.h"

class LocalSession final : public std::enable_shared_from_this<LocalSession> {
public:
    LocalSession(boost::asio::io_service &io_service,
                 boost::asio::ip::tcp::socket &&socket);
    void run();

private:
    void doSocks5HandShakePhase1();
    void doSocks5HandShakePhase2();
    void doSocks5HandleAtyp1();
    void doSocks5HandleAtyp3();

private:
    char buf[4096];
    boost::asio::io_service &service_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::socket rsocket_;
};

class Local final : public std::enable_shared_from_this<Local> {
public:
    Local(boost::asio::io_service &io_service);
    void run();
    void stop();

private:
    void doAccept();

private:
    boost::asio::io_service &service_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::resolver resolver_;
};

#endif // SHADOWSOCKS_ASIO_LOCALSERVER_H
