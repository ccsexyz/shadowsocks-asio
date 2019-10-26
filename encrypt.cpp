#include "encrypt.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/aes.h"
#include "cryptopp/blowfish.h"
#include "cryptopp/cast.h"
#include "cryptopp/chacha.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/des.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/md5.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/salsa.h"

using CryptoPP::AES;
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Blowfish;
using CryptoPP::byte;
using CryptoPP::CAST;
using CryptoPP::CFB_Mode;
using CryptoPP::ChaCha20;
using CryptoPP::DES;
using CryptoPP::Exception;
using CryptoPP::Salsa20;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

template <typename T, const int keyLen, const int ivLen> class Encrypter : public BaseEncrypter {
public:
    Encrypter(const std::string &pwd)
    {
        auto key = evpBytesToKey(pwd, keyLen);
        AutoSeededRandomPool prng;
        byte iv[ivLen];
        prng.GenerateBlock(iv, ivLen);
        iv_ = std::string(std::begin(iv), std::end(iv));
        enc_.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.length(),
            reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
    }
    std::string getIV() override { return iv_; }
    void encrypt(const char *in, std::size_t in_sz, char *out, std::size_t out_sz) override
    {
        ArraySource((const byte *)in, in_sz, true,
            new StreamTransformationFilter(enc_, new ArraySink((byte *)out, out_sz)));
    }
    std::size_t getIvLen() override { return ivLen; }

private:
    std::string iv_;
    typename CFB_Mode<T>::Encryption enc_;
};

template <typename T, const int keyLen, const int ivLen> class Decrypter : public BaseDecrypter {
public:
    Decrypter(const std::string &pwd) { key_ = evpBytesToKey(pwd, keyLen); }
    void initIV(const std::string &iv) override
    {
        dec_.SetKeyWithIV(reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
            reinterpret_cast<const byte *>(iv.c_str()), iv.length());
    }
    std::size_t getIvLen() override { return ivLen; }
    void decrypt(const char *in, std::size_t in_sz, char *out, std::size_t out_sz) override
    {
        ArraySource((const byte *)in, in_sz, true,
            new StreamTransformationFilter(dec_, new ArraySink((byte *)out, out_sz)));
    }

private:
    std::string key_;
    typename CFB_Mode<T>::Decryption dec_;
};

template <const int keyLen, const int ivLen>
class Encrypter<ChaCha20, keyLen, ivLen> : public BaseEncrypter {
public:
    Encrypter(const std::string &pwd)
    {
        auto key = evpBytesToKey(pwd, keyLen);
        AutoSeededRandomPool prng;
        byte iv[ivLen];
        prng.GenerateBlock(iv, ivLen);
        iv_ = std::string(std::begin(iv), std::end(iv));
        enc_.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.length(),
            reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
    }
    std::string getIV() override { return iv_; }
    void encrypt(const char *in, std::size_t in_sz, char *out, std::size_t out_sz) override
    {
        ArraySource((const byte *)in, in_sz, true,
            new StreamTransformationFilter(enc_, new ArraySink((byte *)out, out_sz)));
    }
    std::size_t getIvLen() override { return ivLen; }

private:
    std::string iv_;
    ChaCha20::Encryption enc_;
};

template <const int keyLen, const int ivLen>
class Decrypter<ChaCha20, keyLen, ivLen> : public BaseDecrypter {
public:
    Decrypter(const std::string &pwd) { key_ = evpBytesToKey(pwd, keyLen); }
    void initIV(const std::string &iv) override
    {
        dec_.SetKeyWithIV(reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
            reinterpret_cast<const byte *>(iv.c_str()), iv.length());
    }
    std::size_t getIvLen() override { return ivLen; }
    void decrypt(const char *in, std::size_t in_sz, char *out, std::size_t out_sz) override
    {
        ArraySource((const byte *)in, in_sz, true,
            new StreamTransformationFilter(dec_, new ArraySink((byte *)out, out_sz)));
    }

private:
    std::string key_;
    ChaCha20::Decryption dec_;
};

template <const int keyLen, const int ivLen>
class Encrypter<Salsa20, keyLen, ivLen> : public BaseEncrypter {
public:
    Encrypter(const std::string &pwd)
    {
        auto key = evpBytesToKey(pwd, keyLen);
        AutoSeededRandomPool prng;
        byte iv[ivLen];
        prng.GenerateBlock(iv, ivLen);
        iv_ = std::string(std::begin(iv), std::end(iv));
        enc_.SetKeyWithIV(reinterpret_cast<const byte *>(key.c_str()), key.length(),
            reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
    }
    std::string getIV() override { return iv_; }
    void encrypt(const char *in, std::size_t in_sz, char *out, std::size_t out_sz) override
    {
        ArraySource((const byte *)in, in_sz, true,
            new StreamTransformationFilter(enc_, new ArraySink((byte *)out, out_sz)));
    }
    std::size_t getIvLen() override { return ivLen; }

private:
    std::string iv_;
    Salsa20::Encryption enc_;
};

template <const int keyLen, const int ivLen>
class Decrypter<Salsa20, keyLen, ivLen> : public BaseDecrypter {
public:
    Decrypter(const std::string &pwd) { key_ = evpBytesToKey(pwd, keyLen); }
    void initIV(const std::string &iv) override
    {
        dec_.SetKeyWithIV(reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
            reinterpret_cast<const byte *>(iv.c_str()), iv.length());
    }
    std::size_t getIvLen() override { return ivLen; }
    void decrypt(const char *in, std::size_t in_sz, char *out, std::size_t out_sz) override
    {
        ArraySource((const byte *)in, in_sz, true,
            new StreamTransformationFilter(dec_, new ArraySink((byte *)out, out_sz)));
    }

private:
    std::string key_;
    Salsa20::Decryption dec_;
};

std::unique_ptr<BaseEncrypter> getEncrypter(const std::string &method, const std::string &pwd)
{
    if (method == "aes-128-cfb") {
        return std::move(std::make_unique<Encrypter<AES, 16, 16>>(pwd));
    } else if (method == "aes-192-cfb") {
        return std::move(std::make_unique<Encrypter<AES, 24, 16>>(pwd));
    } else if (method == "des-cfb") {
        return std::move(std::make_unique<Encrypter<DES, 8, 8>>(pwd));
    } else if (method == "bf-cfb") {
        return std::move(std::make_unique<Encrypter<Blowfish, 16, 8>>(pwd));
    } else if (method == "chacha20") {
        return std::move(std::make_unique<Encrypter<ChaCha20, 32, 8>>(pwd));
    } else if (method == "salsa20") {
        return std::move(std::make_unique<Encrypter<Salsa20, 32, 8>>(pwd));
    } else {
        return std::move(std::make_unique<Encrypter<AES, 32, 16>>(pwd));
    }
}

std::unique_ptr<BaseDecrypter> getDecrypter(const std::string &method, const std::string &pwd)
{
    if (method == "aes-128-cfb") {
        return std::move(std::make_unique<Decrypter<AES, 16, 16>>(pwd));
    } else if (method == "aes-192-cfb") {
        return std::move(std::make_unique<Decrypter<AES, 24, 16>>(pwd));
    } else if (method == "des-cfb") {
        return std::move(std::make_unique<Decrypter<DES, 8, 8>>(pwd));
    } else if (method == "bf-cfb") {
        return std::move(std::make_unique<Decrypter<Blowfish, 16, 8>>(pwd));
    } else if (method == "chacha20") {
        return std::move(std::make_unique<Decrypter<ChaCha20, 32, 8>>(pwd));
    } else if (method == "salsa20") {
        return std::move(std::make_unique<Decrypter<Salsa20, 32, 8>>(pwd));
    } else {
        return std::move(std::make_unique<Decrypter<AES, 32, 16>>(pwd));
    }
}

std::string md5Sum(std::string input)
{
    byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];
    CryptoPP::Weak::MD5 hash;
    hash.CalculateDigest(digest, reinterpret_cast<const byte *>(input.c_str()), input.length());
    return std::string(reinterpret_cast<char *>(digest), sizeof(digest));
}

std::string evpBytesToKey(std::string password, int keyLen)
{
    const int md5Len = 16;

    int cnt = (keyLen - 1) / md5Len + 1;
    std::vector<char> vc(cnt * md5Len, 0);
    std::string psdMd5Sum = md5Sum(password);
    std::copy(psdMd5Sum.cbegin(), psdMd5Sum.cend(), vc.begin());

    std::vector<char> vd(md5Len + password.length(), 0);
    int start = 0;
    for (int i = 1; i < cnt; i++) {
        start += md5Len;
        std::copy_n(vc.cbegin() + (start - md5Len), md5Len, vd.begin());
        std::copy(password.cbegin(), password.cend(), vd.begin() + md5Len);
        auto psdMd5Sum2 = md5Sum(std::string(vd.cbegin(), vd.cend()));
        std::copy_n(psdMd5Sum2.cbegin(),
            std::min(static_cast<int>(psdMd5Sum2.length()), cnt * md5Len - start),
            vc.begin() + start);
    }
    return std::string(vc.cbegin(), vc.cbegin() + keyLen);
}