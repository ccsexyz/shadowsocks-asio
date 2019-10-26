#include "UdpServer.h"

UdpServer::UdpServer(asio::io_service &io_service, const config &config)
    : config_(config)
    , service_(io_service)
    , usocket_(io_service,
          asio::ip::udp::endpoint(
              asio::ip::address::from_string(config.remote_addr), config.remote_port))
    , resolver_(io_service)
{
}

void UdpServer::run() { doReceive(); }

void UdpServer::doReceive()
{
    auto self = shared_from_this();
    usocket_.async_receive_from(asio::buffer(buf, sizeof(buf)), endpoint_,
        [this, self](std::error_code ec, std::size_t length) { handleReceive(ec, length); });
}

void UdpServer::handleReceive(std::error_code ec, std::size_t length)
{
    if (ec) {
        usocket_.cancel();
        return;
    }
    auto dec = getDecrypter(config_.method, config_.password);
    auto ivlen = dec->getIvLen();
    char *data = buf;
    if (length <= ivlen) {
        doReceive();
        return;
    }
    dec->initIV(std::string(data, ivlen));
    data += ivlen;
    length -= ivlen;
    dec->decrypt(data, length, buf, length);
    data = buf;
    if (length <= 2) {
        doReceive();
        return;
    }
    auto atyp = data[0];
    data++;
    length--;
    auto self = shared_from_this();
    if (atyp == typeIPv4) {
        if (length <= lenIPv4 + 2) {
            doReceive();
            return;
        }
        auto ep
            = asio::ip::udp::endpoint(asio::ip::address_v4(ntohl(*reinterpret_cast<long *>(data))),
                ntohs(*reinterpret_cast<uint16_t *>(data + lenIPv4)));
        data += lenIPv4 + lenPort;
        length -= lenIPv4 + lenPort;
        //        if(ep.address().to_string() == "8.8.8.8") {
        //            ep =
        //            asio::ip::udp::endpoint(asio::ip::address_v4::from_string("223.6.6.6"),
        //            ep.port());
        //        }
        sendDataFromLocal(
            ep, std::string(data - lenIPv4 - lenPort - 1, lenIPv4 + lenPort + 1), data, length);
    } else if (atyp == typeIPv6) {
        if (length <= lenIPv6) {
            doReceive();
            return;
        }
        asio::ip::address_v6::bytes_type bytes;
        std::copy_n(data, bytes.size(), bytes.data());
        auto ep = asio::ip::udp::endpoint(
            asio::ip::address_v6(bytes), ntohs(*reinterpret_cast<uint16_t *>(data + lenIPv6)));
        data += lenIPv6 + lenPort;
        length -= lenIPv6 + lenPort;
        sendDataFromLocal(
            ep, std::string(data - lenIPv6 - lenPort - 1, lenIPv6 + lenPort + 1), data, length);
    } else if (atyp == typeDm) {
        unsigned char len = data[0];
        data++;
        length--;
        if (length <= len + 2) {
            doReceive();
            return;
        }
        std::string name(data, len);
        data += len;
        length -= len;
        uint16_t port = ntohs(*reinterpret_cast<uint16_t *>(data));
        asio::ip::udp::resolver::query query(name, std::to_string(port));
        data += 2;
        length -= 2;
        std::string header(data - len - 3, len + 3);
        auto self = shared_from_this();
        resolver_.async_resolve(query,
            [this, self, data, length, header](
                std::error_code ec, asio::ip::udp::resolver::iterator iterator) {
                if (ec) {
                    doReceive();
                    return;
                }
                auto ep = *iterator;
                sendDataFromLocal(ep, header, data, length);
            });
    } else {
        doReceive();
        return;
    }
}

void UdpServer::sendDataFromLocal(
    asio::ip::udp::endpoint ep, std::string header, char *data, std::size_t len)
{
    auto self = shared_from_this();
    log_info("[udp] %s:%d", ep.address().to_string().c_str(), ep.port());
    auto it = sessions_.find(endpoint_);
    if (it == sessions_.end()) {
        sessions_.emplace(
            endpoint_, UdpSession(asio::ip::udp::socket(service_, asio::ip::udp::v4())));
        recvDataFromRemote(endpoint_);
        it = sessions_.find(endpoint_);
    }
    headers_.emplace(ep, std::move(header));
    auto &session = it->second;
    auto &usocket = session.usocket_;
    usocket.async_send_to(
        asio::buffer(data, len), ep, [this, self](std::error_code ec, std::size_t length) {
            doReceive();
            return;
        });
}

void UdpServer::doRecvDataFromRemote(
    asio::ip::udp::endpoint ep, std::error_code ec, std::size_t length)
{
    if (ec) {
        sessions_.erase(ep);
        return;
    }
    auto self = shared_from_this();
    auto enc = getEncrypter(config_.method, config_.password);
    auto iv = enc->getIV();
    auto ivlen = enc->getIvLen();
    auto it = sessions_.find(ep);
    auto &session = it->second;
    char *rbuf = session.rbuf;
    auto dstHeader = headers_[session.endpoint_];
    auto dstBody = std::string(rbuf, length);
    std::copy_n(iv.begin(), ivlen, rbuf);
    enc->encrypt(dstHeader.data(), dstHeader.size(), rbuf + ivlen, dstHeader.size());
    enc->encrypt(dstBody.data(), dstBody.size(), rbuf + ivlen + dstHeader.size(), dstBody.size());
    ivlen += dstHeader.length() + dstBody.length();

    usocket_.async_send_to(
        asio::buffer(rbuf, ivlen), ep, [this, self, ep](std::error_code ec, std::size_t length) {
            if (ec) {
                sessions_.erase(ep);
                return;
            }
            recvDataFromRemote(ep);
        });
}

void UdpServer::recvDataFromRemote(asio::ip::udp::endpoint ep)
{
    auto self = shared_from_this();
    auto dt = std::make_shared<asio::high_resolution_timer>(service_, std::chrono::seconds(16));
    auto it = sessions_.find(ep);
    auto &session = it->second;
    session.usocket_.async_receive_from(asio::buffer(session.rbuf, sizeof(session.rbuf)),
        session.endpoint_, [this, self, ep, dt](std::error_code ec, std::size_t length) {
            dt->cancel();
            doRecvDataFromRemote(ep, ec, length);
        });
    dt->async_wait([dt, &session](const std::error_code &) { session.usocket_.cancel(); });
}
