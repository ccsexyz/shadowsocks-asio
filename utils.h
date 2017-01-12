#ifndef SHADOWSOCKS_ASIO_UTILS_H
#define SHADOWSOCKS_ASIO_UTILS_H

#include <algorithm>
#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <streambuf>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <boost/log/trivial.hpp>
#include <boost/log/common.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <random>
#include <type_traits>
#include <utility>
#include <tuple>

namespace logging = boost::log;
using functor = std::function<void()>;

const int AddrMask = 0xf;
const int OneTimeAuthMask = 0x10;

const int idType = 0;
const int idIP0 = 1;
const int idDmLen = 1;
const int idDm0 = 2;

const int typeIPv4 = 1;
const int typeDm = 3;
const int typeIPv6 = 4;

const int lenIPv4 = 6;
const int lenIPv6 = 18;

#define LOG_TRACE                                                              \
//    std::cout << __FILE__ << " " << __func__ << " " << __LINE__ << std::endl;

void printVersion();

bool checkDaemon();

void initLogging();

bool checkAddress(std::string address);

void runAfter(boost::asio::io_service &io_service, boost::posix_time::time_duration td, functor f);

std::size_t getRandomNumber();

class BaseEncrypter;
class BaseDecrypter;

std::unique_ptr<BaseEncrypter> getEncrypter(const std::string &method, const std::string &pwd);

std::unique_ptr<BaseDecrypter> getDecrypter(const std::string &method, const std::string &pwd);

//std::size_t getKeyLen(const std::string &method);
//
//std::size_t getIvLen(const std::string &method);

#if __cplusplus < 201402L
// support make_unique in c++ 11
namespace std {
template <typename T, typename... Args>
inline typename enable_if<!is_array<T>::value, unique_ptr<T>>::type
make_unique(Args &&... args) {
    return unique_ptr<T>(new T(std::forward<Args>(args)...));
}

template <typename T>
inline typename enable_if<is_array<T>::value && extent<T>::value == 0,
                          unique_ptr<T>>::type
make_unique(size_t size) {
    using U = typename remove_extent<T>::type;
    return unique_ptr<T>(new U[size]());
}

template <typename T, typename... Args>
typename enable_if<extent<T>::value != 0, void>::type
make_unique(Args &&...) = delete;
}

#endif

void plusOneSecond(boost::asio::io_service &service, boost::asio::ip::tcp::socket &&s);

#endif // SHADOWSOCKS_ASIO_UTILS_H
