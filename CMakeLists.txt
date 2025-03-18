cmake_minimum_required(VERSION 3.28)
project(traffic_test)

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(traffic_test
        src/main.cpp
        src/capture_module.cpp
        src/control_module.cpp
        src/filter_module.cpp
        src/save_module.cpp)

target_link_libraries(traffic_test PRIVATE ${PCAP_LIBRARIES})
