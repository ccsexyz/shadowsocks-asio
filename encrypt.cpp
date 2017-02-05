#include "encrypt.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/cast.h>
#include <cryptopp/des.h>
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>
#include <cryptopp/salsa.h>

std::string md5Sum(std::string input) {
    byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];
    CryptoPP::Weak::MD5 hash;
    hash.CalculateDigest(digest, reinterpret_cast<const byte *>(input.c_str()),
                         input.length());
    return std::string(reinterpret_cast<char *>(digest), sizeof(digest));
}

std::string evpBytesToKey(std::string password, int keyLen) {
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
                    std::min(static_cast<int>(psdMd5Sum2.length()),
                             cnt * md5Len - start),
                    vc.begin() + start);
    }
    return std::string(vc.cbegin(), vc.cbegin() + keyLen);
}

Cipher::Cipher(std::string method, std::string password) {
    enc_.SetKeyWithIV(
        reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
        reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
    dec_.SetKeyWithIV(
        reinterpret_cast<const byte *>(key_.c_str()), key_.length(),
        reinterpret_cast<const byte *>(iv_.c_str()), iv_.length());
}

std::string Cipher::decrypt(std::string src) {
    std::string secret;
    StringSource(src, true,
                 new StreamTransformationFilter(enc_, new StringSink(secret)));
    return secret;
}

std::string Cipher::encrypt(std::string src) {
    std::string plain;
    StringSource(src, true,
                 new StreamTransformationFilter(dec_, new StringSink(plain)));
    return plain;
}
