#ifndef SHADOWSOCKS_ASIO_UDPSERVER_H
#define SHADOWSOCKS_ASIO_UDPSERVER_H

#include "config.h"
#include "encrypt.h"

struct UdpSession final {
public:
    UdpSession(boost::asio::ip::udp::socket &&socket)
        : usocket_(std::move(socket)) {}
    UdpSession(const UdpSession &) = delete;
    UdpSession(UdpSession &&u) : usocket_(std::move(u.usocket_)) {}
    char buf[65536];
    char rbuf[65536];
    boost::asio::ip::udp::socket usocket_;
    boost::asio::ip::udp::endpoint endpoint_;
};

class UdpServer final : public std::enable_shared_from_this<UdpServer> {
public:
    UdpServer(boost::asio::io_service &io_service, const Config &config);
    void run();

private:
    void doReceive();
    void handleReceive(boost::system::error_code ec, std::size_t length);
    void sendDataFromLocal(boost::asio::ip::udp::endpoint ep,
                           std::string header, char *data, std::size_t len);
    void recvDataFromRemote(boost::asio::ip::udp::endpoint ep);
    void doRecvDataFromRemote(boost::asio::ip::udp::endpoint ep,
                              boost::system::error_code ec, std::size_t length);

private:
    char buf[65536];
    char rbuf[65536];
    Config config_;
    boost::asio::io_service &service_;
    boost::asio::ip::udp::socket usocket_;
    boost::asio::ip::udp::endpoint endpoint_;
    boost::asio::ip::udp::resolver resolver_;
    std::map<boost::asio::ip::udp::endpoint, UdpSession> sessions_;
    std::map<boost::asio::ip::udp::endpoint, std::string> headers_;
};

#endif // SHADOWSOCKS_ASIO_UDPSERVER_H
