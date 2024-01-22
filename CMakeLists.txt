cmake_minimum_required(VERSION 3.17)
project(TestWork)

set(CMAKE_CXX_FLAGS  -static-libstdc++)
set(CMAKE_CXX_FLAGS  -static-libgcc)


set(CMAKE_CXX_FLAGS_RELEASE True)
set(CMAKE_CXX_STANDARD 14)
SET(CMAKE_MODULE_PATH "/C:/TestWork/")
#seT(PCAP_LIBRARIES C:/PCAP/Lib/x64/wpcap.lib C:/PCAP/Lib/x64/Packet.lib)

include_directories(.)
include_directories(C:/PCAP/Include C:/PCAP/Lib)
include(FindPCAP.cmake)

add_executable(TestWork
        main.cpp)

target_link_libraries(TestWork ${PCAP_LIBRARY})
target_link_libraries(TestWork -static)