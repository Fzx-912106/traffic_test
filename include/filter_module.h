#ifndef FILTER_MODULE_H
#define FILTER_MODULE_H

#include "packet.h"
#include <map>
#include <regex>

class FilterModule {
private:
    std::map<std::string, std::vector<std::byte> > tcp_streams;
    std::regex http_response_regex{R"(HTTP/\d\.\d\s+(\d+).*?)"};

public:
    FilterModule() = default;

    std::vector<HttpResponse> filter_http(const std::vector<Packet> &packets);

    HttpResponse parse_http_response(const std::vector<std::byte> &data,
                                     const std::string &url);

    std::string determine_file_extension(const std::string &content_type,
                                         const std::vector<std::byte> &data,
                                         const std::string &url);

    std::string detect_by_magic_numbers(const std::vector<std::byte> &data);
};

#endif // FILTER_MODULE_H


//// =========== 过滤模块 ===========
//class FilterModule {
//private:
//    std::map<std::string, std::vector<std::byte> > tcp_streams;
//    std::regex http_response_regex{R"(HTTP/\d\.\d\s+(\d+).*?)"};
//
//public:
//    FilterModule() = default;
//
//    std::vector<HttpResponse> filter_http(const std::vector<Packet> &packets);
//
//    HttpResponse parse_http_response(const std::vector<std::byte> &data,
//                                     const std::string &url);
//
//    std::string determine_file_extension(const std::string &content_type,
//                                         const std::vector<std::byte> &data,
//                                         const std::string &url);
//    std::string detect_by_magic_numbers(const std::vector<std::byte> &data); //添加文件类型签名检测（文件内容魔数检测）
//};
