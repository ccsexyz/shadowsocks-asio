#include "UdpServer.h"

UdpSession::UdpSession(asio::io_service &io_service, std::shared_ptr<UdpServer> server,
    asio::ip::udp::endpoint from_endpoint, const Config &config)
    : config_(config), service_(io_service), strand_(io_service),
    from_endpoint_(from_endpoint), server_(server),
    timeout_timer_(io_service), usocket_(io_service), resolver_(io_service) {}

UdpSession::~UdpSession() {
    auto server = server_.lock();
    if (server) {
        server->remove_session(from_endpoint_);
    }
}

void UdpSession::run() {
    auto self = shared_from_this();
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        wait_and_process_first_packet(yield);
    }, default_coroutines_attr);
    timeout_timer_.expires_from_now(std::chrono::seconds(4));
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        timeout(yield);
    }, default_coroutines_attr);
}

void UdpSession::destroy() {
    destroyed_ = true;
    bufch_.notify_all();
    usocket_.close();
}

void UdpSession::timeout(asio::yield_context yield) {
    while (!destroyed_) {
        std::error_code ec;
        timeout_timer_.async_wait(yield[ec]);
        if (timeout_timer_.expires_from_now() <= std::chrono::seconds(0)) {
            destroy();
        }
    }
}

std::string UdpSession::recv_packet(asio::yield_context yield) {
    while (buffers_.empty()) {
        bufch_.wait(service_, yield);
        if (destroyed_) {
            return "";
        }
    }
    auto buffer = buffers_[0];
    buffers_.pop_front();
    return buffer;
}

void UdpSession::wait_and_process_first_packet(asio::yield_context yield) {
    std::error_code ec;
    auto self = shared_from_this();
    std::string buffer = recv_packet(yield);
    if (destroyed_) {
        return;
    }
    auto dec = getDecrypter(config_.Method, config_.Password);
    auto ivlen = dec->getIvLen();
    auto n = buffer.size();
    if (n < ivlen) {
        return;
    }
    dec->initIV(buffer.substr(0, ivlen));
    std::string plain = dec->decrypt(buffer.substr(ivlen, n));
    char *data = const_cast<char *>(plain.data());
    n = plain.size();
    if (n <= 2) {
        return;
    }
    auto atyp = data[0];
    if (atyp == typeIPv4) {
        if (n < lenIPv4 + 2 + 1) {
            return;
        }
        endpoint_ = asio::ip::udp::endpoint(
            asio::ip::address_v4(ntohl(*reinterpret_cast<long *>(data + 1))),
            ntohs(*reinterpret_cast<uint16_t *>(data + lenIPv4 + 1)));
        hdrsz_ = lenIPv4 + 2 + 1;
    } else if (atyp == typeIPv6) {
        if (n < lenIPv6 + 2 + 1) {
            return;
        }
        asio::ip::address_v6::bytes_type bytes;
        std::copy_n(data + 1, bytes.size(), bytes.data());
        endpoint_ = asio::ip::udp::endpoint(
            asio::ip::address_v6(bytes),
            ntohs(*reinterpret_cast<uint16_t *>(data + 1 + lenIPv6)));
        hdrsz_ = lenIPv6 + 2 + 1;
    } else if (atyp == typeDm) {
        unsigned char len = data[1];
        if (n < len + 2 + 2) {
            return;
        }
        std::string name(data + 2, len);
        uint16_t port = ntohs(*reinterpret_cast<uint16_t *>(data + len + 2));
        asio::ip::udp::resolver::query query(name, std::to_string(port));
        auto iterator = resolver_.async_resolve(query, yield[ec]);
        if (ec) {
            return;
        }
        endpoint_ = *iterator;
        hdrsz_ = len + 2 + 2;
    } else {
        return;
    }
    header_ = std::string(data, hdrsz_);
    LOG(INFO) << "[udp] " << endpoint_.address().to_string() << ":" << static_cast<int>(endpoint_.port());
    usocket_.async_connect(endpoint_, yield[ec]);
    if (ec) {
        return;
    }
    usocket_.async_send(asio::buffer(data+hdrsz_, n-hdrsz_), yield[ec]);
    if (ec) {
        return;
    }
    ivlen_ = ivlen;
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        do_pipe1(yield);
    }, default_coroutines_attr);
    asio::spawn(strand_, [this, self](asio::yield_context yield){
        do_pipe2(yield);
    }, default_coroutines_attr);
}

void UdpSession::do_pipe1(asio::yield_context yield) {
    auto self = shared_from_this();
    std::error_code ec;

    for (;;) {
        timeout_timer_.expires_from_now(std::chrono::seconds(4));
        auto buffer = recv_packet(yield);
        if (destroyed_) {
            return;
        }
        auto n = buffer.size();
        auto dec = getDecrypter(config_.Method, config_.Password);
        if (n < ivlen_ + hdrsz_) {
            continue;
        }
        dec->initIV(buffer.substr(0, ivlen_));
        std::string plain = dec->decrypt(buffer.substr(ivlen_, n));
        const char *data = plain.data() + hdrsz_;
        usocket_.async_send(asio::buffer(data, n - ivlen_ - hdrsz_), yield[ec]);
        if (ec) {
            return;
        }
    }
}

void UdpSession::do_pipe2(asio::yield_context yield) {
    auto self = shared_from_this();
    std::error_code ec;
    char buf[2048];
    char *iv = buf;
    char *hdr = buf + ivlen_;
    char *data = buf + ivlen_ + hdrsz_;

    for (;;) {
        timeout_timer_.expires_from_now(std::chrono::seconds(4));
        auto n = usocket_.async_receive(asio::buffer(data, sizeof(buf) - ivlen_ - hdrsz_), yield[ec]);
        if (ec) {
            return;
        }
        auto server = server_.lock();
        if (!server) {
            return;
        }
        auto enc = getEncrypter(config_.Method, config_.Password);
        auto eiv = enc->getIV();
        std::copy_n(eiv.begin(), ivlen_, iv);
        std::copy_n(header_.begin(), hdrsz_, hdr);
        auto edata = enc->encrypt(std::string(hdr, hdrsz_+n));
        std::copy_n(edata.begin(), hdrsz_+n, hdr);
        server->send(from_endpoint_, buf, ivlen_+hdrsz_+n, yield);
    }
}

void UdpSession::send(const char *buf, std::size_t length) {
    if (destroyed_) {
        return;
    }
    buffers_.emplace_back(buf, length);
    bufch_.notify_one();
}

UdpServer::UdpServer(asio::io_service &io_service, const Config &config)
    : config_(config), service_(io_service),
      usocket_(io_service,
               asio::ip::udp::endpoint(
                   asio::ip::address::from_string(config.ServerAddress),
                   config.ServerPort)) {}

void UdpServer::run() {
    auto self = shared_from_this();
    asio::spawn(service_, [this, self](asio::yield_context yield){
        recv_loop(yield);
    }, default_coroutines_attr);
}

void UdpServer::recv_loop(asio::yield_context yield) {
    auto self = shared_from_this();
    asio::ip::udp::endpoint last_endpoint;
    std::weak_ptr<UdpSession> last_session;

    for (;;) {
        std::error_code ec;
        auto n = usocket_.async_receive_from(asio::buffer(buf, sizeof(buf)), endpoint_, yield[ec]);
        if (ec) {
            usocket_.cancel();
            return;
        }
        std::shared_ptr<UdpSession> udp_sess;
        auto it = sessions_.find(endpoint_);
        if (it != sessions_.end()) {
            auto &weak_sess = it->second;
            udp_sess = weak_sess.lock();
        }
        if (!udp_sess) {
            udp_sess = std::make_shared<UdpSession>(service_, self,
                endpoint_, config_);
            sessions_.emplace(endpoint_, udp_sess);
            udp_sess->run();
        }
        last_endpoint = endpoint_;
        last_session = udp_sess;
        udp_sess->send(buf, n);
    }
}

UdpServer::~UdpServer() {
    destroy();
}

void UdpServer::destroy() {
    for (auto &weak_sess : sessions_) {
        auto sess = weak_sess.second.lock();
        if (!sess) {
            continue;
        }
        sess->destroy();
    }
    sessions_.clear();
}

void UdpServer::remove_session(asio::ip::udp::endpoint endpoint) {
    sessions_.erase(endpoint);
}

void UdpServer::send(const asio::ip::udp::endpoint &ep, const char *buf, std::size_t n, asio::yield_context yield) {
    std::error_code ec;
    usocket_.async_send_to(asio::buffer(buf, n), ep, yield[ec]);
    if (ec) {
        destroy();
    }
}
