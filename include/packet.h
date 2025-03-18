#ifndef PACKET_H
#define PACKET_H

#include <chrono>
#include <vector>
#include <string>
#include <cstdint>
#include <map>

// =========== 常量 ===========
constexpr int HTTP_PORT = 80;
constexpr int HTTPS_PORT = 443;
constexpr int MAX_PACKET_SIZE = 65535;

// =========== 数据包结构 ===========
struct Packet {
    std::vector<std::byte> data;
    size_t length;
    std::chrono::system_clock::time_point timestamp;
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
};

struct HttpResponse {
    int status_code;
    std::map<std::string, std::string> headers;
    std::vector<std::byte> body;
    std::string content_type;
    std::string url;
    std::string filename;
};

#endif // PACKET_H
