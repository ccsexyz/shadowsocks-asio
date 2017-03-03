cmake_minimum_required(VERSION 3.5)
project(shadowsocks_asio)

#SET (CMAKE_C_COMPILER             "/usr/bin/clang")
#SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES utils.h utils.cpp config.cpp config.h json.h encrypt.cpp encrypt.h Logger.cpp Logger.h)
set(SSSERVER_SOURCE_FILES ssserver.cpp ${SOURCE_FILES} UdpServer.cpp UdpServer.h Server.cpp Server.h)
set(SSLOCAL_SOURCE_FILES sslocal.cpp ${SOURCE_FILES} Local.h Local.cpp)

add_executable(ssserver ${SSSERVER_SOURCE_FILES})
target_link_libraries(ssserver pthread)
target_link_libraries(ssserver cryptopp)
add_executable(sslocal ${SSLOCAL_SOURCE_FILES})
target_link_libraries(sslocal pthread)
target_link_libraries(sslocal cryptopp)