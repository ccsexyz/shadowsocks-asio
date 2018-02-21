#ifndef SHADOWSOCKS_ASIO_UDPSERVER_H
#define SHADOWSOCKS_ASIO_UDPSERVER_H

#include "config.h"
#include "encrypt.h"

class UdpServer;

class UdpSession final : public std::enable_shared_from_this<UdpSession> {
public:
    UdpSession(asio::io_service &io_service,
        std::shared_ptr<UdpServer> server,
        asio::ip::udp::endpoint from_endpoint,
        const Config &config);
    UdpSession(const UdpSession &) = delete;
    UdpSession(UdpSession &&) = delete;
    ~UdpSession();
    void destroy();
    void run();
    void send(const char *buf, std::size_t length);

private:
    void timeout(asio::yield_context yield);
    std::string recv_packet(asio::yield_context yield);
    void wait_and_process_first_packet(asio::yield_context yield);
    void do_pipe1(asio::yield_context yield);
    void do_pipe2(asio::yield_context yield);

private:
    bool destroyed_ = false;
    std::size_t ivlen_;
    std::size_t hdrsz_;
    std::string header_;
    Config config_;
    asio::io_service &service_;
    asio::io_service::strand strand_;
    asio::ip::udp::endpoint endpoint_;
    asio::ip::udp::endpoint from_endpoint_;
    std::deque<std::string> buffers_;
    AsioCondVar bufch_;
    std::weak_ptr<UdpServer> server_;
    asio::high_resolution_timer timeout_timer_;
    asio::ip::udp::socket usocket_;
    asio::ip::udp::resolver resolver_;
};

class UdpServer final : public std::enable_shared_from_this<UdpServer> {
public:
    UdpServer(asio::io_service &io_service, const Config &config);
    ~UdpServer();
    void run();
    void send(const asio::ip::udp::endpoint &ep, const char *buf, std::size_t n, asio::yield_context yield);
    void remove_session(asio::ip::udp::endpoint endpoint);
    void destroy();

private:
    void recv_loop(asio::yield_context yield);

private:
    char buf[2048];
    Config config_;
    asio::io_service &service_;
    asio::ip::udp::socket usocket_;
    asio::ip::udp::endpoint endpoint_;
    std::map<asio::ip::udp::endpoint, std::weak_ptr<UdpSession>> sessions_;
};

#endif // SHADOWSOCKS_ASIO_UDPSERVER_H
