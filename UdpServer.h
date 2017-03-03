#ifndef SHADOWSOCKS_ASIO_UDPSERVER_H
#define SHADOWSOCKS_ASIO_UDPSERVER_H

#include "config.h"
#include "encrypt.h"

struct UdpSession final {
public:
    UdpSession(asio::ip::udp::socket &&socket)
        : usocket_(std::move(socket)) {}
    UdpSession(const UdpSession &) = delete;
    UdpSession(UdpSession &&u) : usocket_(std::move(u.usocket_)) {}
    char buf[65536];
    char rbuf[65536];
    asio::ip::udp::socket usocket_;
    asio::ip::udp::endpoint endpoint_;
};

class UdpServer final : public std::enable_shared_from_this<UdpServer> {
public:
    UdpServer(asio::io_service &io_service, const Config &config);
    void run();

private:
    void doReceive();
    void handleReceive(std::error_code ec, std::size_t length);
    void sendDataFromLocal(asio::ip::udp::endpoint ep,
                           std::string header, char *data, std::size_t len);
    void recvDataFromRemote(asio::ip::udp::endpoint ep);
    void doRecvDataFromRemote(asio::ip::udp::endpoint ep,
                              std::error_code ec, std::size_t length);

private:
    char buf[65536];
    char rbuf[65536];
    Config config_;
    asio::io_service &service_;
    asio::ip::udp::socket usocket_;
    asio::ip::udp::endpoint endpoint_;
    asio::ip::udp::resolver resolver_;
    std::map<asio::ip::udp::endpoint, UdpSession> sessions_;
    std::map<asio::ip::udp::endpoint, std::string> headers_;
};

#endif // SHADOWSOCKS_ASIO_UDPSERVER_H
