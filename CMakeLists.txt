cmake_minimum_required(VERSION 3.30)
project(traffic_test)

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(traffic_test main.cpp
        inc/capture.hpp
        inc/control.hpp
        inc/filter.hpp
        inc/packet.hpp
        inc/save.hpp)

target_link_libraries(traffic_test PRIVATE ${PCAP_LIBRARIES})
