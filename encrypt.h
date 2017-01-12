//
// Created by JohnsonJohn on 2017/1/10.
//

#ifndef SHADOWSOCKS_ASIO_ENCRYPT_H
#define SHADOWSOCKS_ASIO_ENCRYPT_H

#include "config.h"
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/des.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/cast.h>
#include <cryptopp/chacha.h>
#include <cryptopp/salsa.h>
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Exception;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::DES;
using CryptoPP::Blowfish;
using CryptoPP::CAST;
using CryptoPP::ChaCha20;
using CryptoPP::Salsa20;
using CryptoPP::CFB_Mode;

class Cipher final {
public:
    Cipher(std::string method, std::string password);
    std::string encrypt(std::string src);
    std::string decrypt(std::string src);
private:
    std::string key_;
    std::string iv_;
    CFB_Mode<AES>::Encryption enc_;
    CFB_Mode<AES>::Decryption dec_;
};

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

template<typename T, const int keyLen, const int ivLen>
class Encrypter : public BaseEncrypter {
public:
    Encrypter(const std::string &pwd) {
        auto key = evpBytesToKey(pwd, keyLen);
        AutoSeededRandomPool prng;
        byte iv[ivLen];
        prng.GenerateBlock(iv, ivLen);
        iv_ = std::string(std::begin(iv), std::end(iv));
        enc_.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.length(),
                          reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
    }
    std::string getIV() override {
        return iv_;
    }
    std::string encrypt(const std::string &str) override {
        std::string secret;
        StringSource(str, true, new StreamTransformationFilter(enc_, new StringSink(secret)));
        return secret;
    }
    std::size_t getIvLen() override {
        return ivLen;
    }

private:
    std::string iv_;
    typename CFB_Mode<T>::Encryption enc_;
};

template<typename T, const int keyLen, const int ivLen>
class Decrypter : public BaseDecrypter {
public:
    Decrypter(const std::string &pwd) {
        key_ = evpBytesToKey(pwd, keyLen);
    }
    void initIV(const std::string &iv) override {
        dec_.SetKeyWithIV(reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
                          reinterpret_cast<const byte *>(iv.c_str()), iv.length());
    }
    std::size_t getIvLen() override {
        return ivLen;
    }
    std::string decrypt(const std::string &str) override {
        std::string plain;
        StringSource(str, true, new StreamTransformationFilter(dec_, new StringSink(plain)));
        return plain;
    }

private:
    std::string key_;
    typename CFB_Mode<T>::Decryption dec_;
};

template<const int keyLen, const int ivLen>
class Encrypter<ChaCha20, keyLen, ivLen> : public BaseEncrypter {
public:
    Encrypter(const std::string &pwd) {
        auto key = evpBytesToKey(pwd, keyLen);
        AutoSeededRandomPool prng;
        byte iv[ivLen];
        prng.GenerateBlock(iv, ivLen);
        iv_ = std::string(std::begin(iv), std::end(iv));
        enc_.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.length(),
                          reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
    }
    std::string getIV() override {
        return iv_;
    }
    std::string encrypt(const std::string &str) override {
        std::string secret;
        StringSource(str, true, new StreamTransformationFilter(enc_, new StringSink(secret)));
        return secret;
    }
    std::size_t getIvLen() override {
        return ivLen;
    }

private:
    std::string iv_;
    ChaCha20::Encryption enc_;
};

template<const int keyLen, const int ivLen>
class Decrypter<ChaCha20, keyLen, ivLen> : public BaseDecrypter {
public:
    Decrypter(const std::string &pwd) {
        key_ = evpBytesToKey(pwd, keyLen);
    }
    void initIV(const std::string &iv) override {
        dec_.SetKeyWithIV(reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
                          reinterpret_cast<const byte *>(iv.c_str()), iv.length());
    }
    std::size_t getIvLen() override {
        return ivLen;
    }
    std::string decrypt(const std::string &str) override {
        std::string plain;
        StringSource(str, true, new StreamTransformationFilter(dec_, new StringSink(plain)));
        return plain;
    }

private:
    std::string key_;
    ChaCha20::Decryption dec_;
};

template<const int keyLen, const int ivLen>
class Encrypter<Salsa20, keyLen, ivLen> : public BaseEncrypter {
public:
    Encrypter(const std::string &pwd) {
        auto key = evpBytesToKey(pwd, keyLen);
        AutoSeededRandomPool prng;
        byte iv[ivLen];
        prng.GenerateBlock(iv, ivLen);
        iv_ = std::string(std::begin(iv), std::end(iv));
        enc_.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.length(),
                          reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
    }
    std::string getIV() override {
        return iv_;
    }
    std::string encrypt(const std::string &str) override {
        std::string secret;
        StringSource(str, true, new StreamTransformationFilter(enc_, new StringSink(secret)));
        return secret;
    }
    std::size_t getIvLen() override {
        return ivLen;
    }

private:
    std::string iv_;
    Salsa20::Encryption enc_;
};

template<const int keyLen, const int ivLen>
class Decrypter<Salsa20, keyLen, ivLen> : public BaseDecrypter {
public:
    Decrypter(const std::string &pwd) {
        key_ = evpBytesToKey(pwd, keyLen);
    }
    void initIV(const std::string &iv) override {
        dec_.SetKeyWithIV(reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
                          reinterpret_cast<const byte *>(iv.c_str()), iv.length());
    }
    std::size_t getIvLen() override {
        return ivLen;
    }
    std::string decrypt(const std::string &str) override {
        std::string plain;
        StringSource(str, true, new StreamTransformationFilter(dec_, new StringSink(plain)));
        return plain;
    }

private:
    std::string key_;
    Salsa20::Decryption dec_;
};

#endif //SHADOWSOCKS_ASIO_ENCRYPT_H
