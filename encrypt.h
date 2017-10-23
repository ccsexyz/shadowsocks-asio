#ifndef SHADOWSOCKS_ASIO_ENCRYPT_H
#define SHADOWSOCKS_ASIO_ENCRYPT_H

#include "config.h"

std::string evpBytesToKey(std::string password, int keyLen);

class BaseEncrypter {
public:
    virtual std::size_t getIvLen() = 0;
    virtual std::string getIV() = 0;
    virtual std::string encrypt(const std::string &) = 0;
};

class BaseDecrypter {
public:
    virtual std::size_t getIvLen() = 0;
    virtual void initIV(const std::string &) = 0;
    virtual std::string decrypt(const std::string &) = 0;
};

std::unique_ptr<BaseEncrypter> getEncrypter(const std::string &method,
    const std::string &pwd);

std::unique_ptr<BaseDecrypter> getDecrypter(const std::string &method,
    const std::string &pwd);

#endif // SHADOWSOCKS_ASIO_ENCRYPT_H
