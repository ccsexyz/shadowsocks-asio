#ifndef SHADOWSOCKS_ASIO_UTILS_H
#define SHADOWSOCKS_ASIO_UTILS_H

#include <algorithm>
#include <arpa/inet.h>
#include "asio.hpp"
#include "asio/spawn.hpp"
#include "asio/high_resolution_timer.hpp"
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
#include <deque>
#include <vector>
#include "glog/logging.h"

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

bool checkAddress(std::string address);

void runAfter(asio::io_service &io_service,
              boost::posix_time::time_duration td, functor f);

std::size_t getRandomNumber();

class clean_ {
public:
    clean_(const clean_ &) = delete;

    clean_(clean_ &&) = delete;

    clean_ &operator=(const clean_ &) = delete;

    clean_() = default;
};

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

class AsioCondVar : clean_ {
public:
    AsioCondVar() = default;

    void notify_n(std::size_t n);
    void notify_one();
    void notify_all();
    void wait(asio::io_service &io_service, asio::yield_context yield);
private:
    std::list<std::weak_ptr<asio::high_resolution_timer>> timers_;
};

template <typename T, std::size_t N>
class AsioChan {
public:
    AsioChan() {
        elements_.reserve(N);
    }
    bool send(T ele, asio::io_service &io_service, asio::yield_context yield) {
        while (elements_.size() >= N) {
            not_full_.wait(io_service, yield);
        }
        elements_.push_back(ele);
        not_empty_.notify_one();
    }
    bool recv(asio::io_service &io_service, asio::yield_context yield, T &ele) {
        while (elements_.size() == 0) {
            not_empty_.wait(io_service, yield);
        }
        T ele_copy = elements_.front();
        elements_.pop_front();
        not_full_.notify_one();
        ele = ele_copy;
    }
private:
    std::deque<T> elements_;
    AsioCondVar not_full_;
    AsioCondVar not_empty_;
};

extern boost::coroutines::attributes default_coroutines_attr;

#endif // SHADOWSOCKS_ASIO_UTILS_H
