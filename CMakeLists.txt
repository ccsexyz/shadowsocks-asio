cmake_minimum_required(VERSION 3.5)
project(shadowsocks_asio)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -DBOOST_LOG_DYN_LINK")

set(SOURCE_FILES utils.h utils.cpp config.cpp config.h json.h Server.cpp Server.h encrypt.cpp encrypt.h)
set(MAIN_SOURCE_FILES main.cpp ${SOURCE_FILES})
set(SSSERVER_SOURCE_FILES ssserver.cpp ${SOURCE_FILES})

add_executable(ssserver ${SSSERVER_SOURCE_FILES})
target_link_libraries(ssserver pthread)
target_link_libraries(ssserver boost_system)
target_link_libraries(ssserver boost_log)
target_link_libraries(ssserver boost_thread)
target_link_libraries(ssserver cryptopp)