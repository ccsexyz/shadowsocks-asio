#ifndef SHADOWSOCKS_ASIO_UTILS_H
#define SHADOWSOCKS_ASIO_UTILS_H

#include <algorithm>
#include <arpa/inet.h>
#include <asio.hpp>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <random>
#include <streambuf>
#include <string>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "Logger.h"

using functor = std::function<void()>;

const int typeIPv4 = 1;
const int typeDm = 3;
const int typeIPv6 = 4;

const int lenIPv4 = 4;
const int lenIPv6 = 16;
const int lenPort = 2;

#define LOG_TRACE                                                              \
//    std::cout << __FILE__ << " " << __func__ << " " << __LINE__ << std::endl;

void printVersion();

bool checkDaemon();

void initLogging();

bool checkAddress(std::string address);

void runAfter(asio::io_service &io_service,
              boost::posix_time::time_duration td, functor f);

std::size_t getRandomNumber();

class BaseEncrypter;
class BaseDecrypter;

std::unique_ptr<BaseEncrypter> getEncrypter(const std::string &method,
                                            const std::string &pwd);

std::unique_ptr<BaseDecrypter> getDecrypter(const std::string &method,
                                            const std::string &pwd);

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

void plusOneSecond(asio::io_service &service,
                   asio::ip::tcp::socket &&s);

using Handler = std::function<void(std::error_code, std::size_t)>;

#endif // SHADOWSOCKS_ASIO_UTILS_H
