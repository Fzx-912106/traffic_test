// 流量分析还原程序
// 使用C++20特性，捕获、过滤和还原HTTP内容
// 使用std::byte代替uint8_t

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include <atomic>
#include <chrono>
#include <cstddef>  // 为std::byte引入
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// 前向声明
class ControlModule;
class CaptureModule;
class FilterModule;
class SaveModule;

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

// =========== 控制模块 ===========
class ControlModule {
private:
    std::shared_ptr<CaptureModule> capture_module;
    std::shared_ptr<FilterModule> filter_module;
    std::shared_ptr<SaveModule> save_module;
    std::atomic<bool> running{false};
    std::string interface;
    std::string output_dir;
    std::string filter_expr;

public:
    ControlModule(const std::string &iface, const std::string &output,
                  const std::string &filter)
        : interface(iface), output_dir(output), filter_expr(filter) {
    }

    void initialize();

    void start();

    void stop();

    void status() const;
};

// =========== 抓包模块 ===========
class CaptureModule {
private:
    pcap_t *handle{nullptr};
    std::string interface;
    std::string filter_expr;
    std::atomic<bool> running{false};
    std::thread capture_thread;
    std::mutex packet_mutex;
    std::vector<Packet> packet_buffer;

    static void packet_handler(u_char *user_data,
                               const struct pcap_pkthdr *pkthdr,
                               const u_char *packet);

    void capture_thread_func();

public:
    CaptureModule(const std::string &iface, const std::string &filter)
        : interface(iface), filter_expr(filter) {
    }

    ~CaptureModule();

    bool initialize();

    void start();

    void stop();

    std::vector<Packet> get_packets();
};

// =========== 过滤模块 ===========
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
    std::string detect_by_magic_numbers(const std::vector<std::byte> &data); //添加文件类型签名检测（文件内容魔数检测）
};

// =========== 保存模块 ===========
class SaveModule {
private:
    std::string output_dir;
    std::mutex save_mutex;

    void ensure_directory_exists(const std::string &dir);

    std::string sanitize_filename(const std::string &filename);

public:
    SaveModule(const std::string &dir) : output_dir(dir) {
    }

    bool initialize();

    bool save_response(const HttpResponse &response);
};

// =========== 控制模块实现 ===========
void ControlModule::initialize() {
    capture_module = std::make_shared<CaptureModule>(interface, filter_expr);
    filter_module = std::make_shared<FilterModule>();
    save_module = std::make_shared<SaveModule>(output_dir);

    if (!capture_module->initialize()) {
        throw std::runtime_error("抓包模块初始化失败");
    }

    if (!save_module->initialize()) {
        throw std::runtime_error("保存模块初始化失败");
    }

    std::cout << "所有模块初始化成功" << std::endl;
}

void ControlModule::start() {
    if (running) {
        std::cout << "流量分析已在运行中" << std::endl;
        return;
    }

    running = true;
    capture_module->start();

    std::cout << "流量分析在接口 " << interface << " 上开始运行" << std::endl;

    // 循环处理数据包
    while (running) {
        // 从抓包模块获取数据包
        auto packets = capture_module->get_packets();
        if (!packets.empty()) {
            std::cout << "正在处理 " << packets.size() << " 个数据包" << std::endl;

            // 过滤HTTP响应
            auto http_responses = filter_module->filter_http(packets);
            std::cout << "发现 " << http_responses.size() << " 个HTTP响应"
                    << std::endl;

            // 保存HTTP响应
            for (const auto &response: http_responses) {
                if (save_module->save_response(response)) {
                    std::cout << "已保存: " << response.filename << std::endl;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    }
}

void ControlModule::stop() {
    if (!running) {
        std::cout << "流量分析未在运行" << std::endl;
        return;
    }

    running = false;
    capture_module->stop();
    std::cout << "流量分析已停止" << std::endl;
}

void ControlModule::status() const {
    std::cout << "流量分析状态:" << std::endl;
    std::cout << "  接口: " << interface << std::endl;
    std::cout << "  输出目录: " << output_dir << std::endl;
    std::cout << "  过滤表达式: " << filter_expr << std::endl;
    std::cout << "  运行状态: " << (running ? "运行中" : "已停止") << std::endl;
}

// =========== 抓包模块实现 ===========
CaptureModule::~CaptureModule() {
    stop();
    if (handle) {
        pcap_close(handle);
    }
}

bool CaptureModule::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 打开网络接口进行数据包捕获
    handle = pcap_open_live(interface.c_str(), MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "打开接口 " << interface << " 出错: " << errbuf << std::endl;
        return false;
    }

    // 设置捕获过滤器
    if (!filter_expr.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_expr.c_str(), 0,
                         PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "编译过滤表达式出错: " << pcap_geterr(handle) << std::endl;
            return false;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "设置过滤器出错: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            return false;
        }

        pcap_freecode(&fp);
    }

    return true;
}

void CaptureModule::packet_handler(u_char *user_data,
                                   const struct pcap_pkthdr *pkthdr,
                                   const u_char *packet) {
    auto *capture = reinterpret_cast<CaptureModule *>(user_data);

    // 提取IP头
    const struct ip *ip_header =
            reinterpret_cast<const struct ip *>(packet + 14); // 跳过以太网头
    if (ip_header->ip_p != IPPROTO_TCP) {
        return; // 仅处理TCP数据包
    }

    // 提取TCP头
    int ip_header_length = ip_header->ip_hl * 4;
    const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(
        reinterpret_cast<const uint8_t *>(ip_header) + ip_header_length);

    // 创建数据包对象
    Packet pkt;
    pkt.length = pkthdr->len;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.source_ip = inet_ntoa(ip_header->ip_src);
    pkt.dest_ip = inet_ntoa(ip_header->ip_dst);
    pkt.source_port = ntohs(tcp_header->th_sport);
    pkt.dest_port = ntohs(tcp_header->th_dport);

    // 复制数据包数据
    pkt.data.resize(pkthdr->len);
    for (size_t i = 0; i < pkthdr->len; i++) {
        pkt.data[i] = static_cast<std::byte>(packet[i]);
    }

    // 添加到缓冲区
    std::lock_guard<std::mutex> lock(capture->packet_mutex);
    capture->packet_buffer.push_back(std::move(pkt));
}

void CaptureModule::capture_thread_func() {
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char *>(this));
}

void CaptureModule::start() {
    if (running) {
        return;
    }

    running = true;
    capture_thread = std::thread(&CaptureModule::capture_thread_func, this);
}

void CaptureModule::stop() {
    if (!running) {
        return;
    }

    running = false;
    pcap_breakloop(handle);

    if (capture_thread.joinable()) {
        capture_thread.join();
    }
}

std::vector<Packet> CaptureModule::get_packets() {
    std::lock_guard<std::mutex> lock(packet_mutex);
    std::vector<Packet> packets = std::move(packet_buffer);
    packet_buffer.clear();
    return packets;
}

// =========== 过滤模块实现 ===========
std::vector<HttpResponse> FilterModule::filter_http(
    const std::vector<Packet> &packets) {
    std::vector<HttpResponse> http_responses;

    // 处理每个数据包并更新TCP流
    for (const auto &packet: packets) {
        // 仅处理HTTP/HTTPS端口上的数据包
        if (packet.source_port != HTTP_PORT && packet.source_port != HTTPS_PORT &&
            packet.dest_port != HTTP_PORT && packet.dest_port != HTTPS_PORT) {
            continue;
        }

        // 提取IP和TCP头
        const auto *ethernetStart = packet.data.data();
        const struct ip *ip_header = reinterpret_cast<const struct ip *>(
            reinterpret_cast<const char *>(ethernetStart) + 14); // 跳过以太网头
        int ip_header_length = ip_header->ip_hl * 4;
        const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(
            reinterpret_cast<const char *>(ip_header) + ip_header_length);
        int tcp_header_length = tcp_header->th_off * 4;

        // 提取载荷
        auto payloadOffset = 14 + ip_header_length + tcp_header_length;
        if (payloadOffset >= packet.length) {
            continue; // 无载荷
        }

        int payload_length = packet.length - payloadOffset;
        if (payload_length <= 0) {
            continue;
        }

        // 创建流密钥（源IP:端口 -> 目标IP:端口）
        std::string stream_key =
                packet.source_ip + ":" + std::to_string(packet.source_port) + "->" +
                packet.dest_ip + ":" + std::to_string(packet.dest_port);

        // 添加载荷到TCP流
        auto &stream = tcp_streams[stream_key];
        size_t old_size = stream.size();
        stream.resize(old_size + payload_length);

        // 复制载荷数据到流
        for (int i = 0; i < payload_length; i++) {
            stream[old_size + i] = packet.data[payloadOffset + i];
        }

        // 检查此流是否包含HTTP响应
        // 将前100字节转换为字符串进行检查
        std::string stream_start;
        size_t check_size = std::min(stream.size(), size_t(100));
        for (size_t i = 0; i < check_size; i++) {
            stream_start.push_back(
                static_cast<char>(std::to_integer<unsigned char>(stream[i])));
        }

        if (stream_start.find("HTTP/") == 0) {
            // 这看起来像一个HTTP响应
            std::string url =
                    packet.source_ip + ":" + std::to_string(packet.source_port);
            HttpResponse response = parse_http_response(stream, url);

            if (!response.body.empty()) {
                http_responses.push_back(response);
                // 处理后清除流以避免重复
                tcp_streams.erase(stream_key);
            }
        }
    }

    return http_responses;
}

HttpResponse FilterModule::parse_http_response(
    const std::vector<std::byte> &data, const std::string &url) {
    HttpResponse response;
    response.url = url;

    // 转换为字符串以便于处理
    std::string data_str;
    data_str.reserve(data.size());
    for (const auto &b: data) {
        data_str.push_back(static_cast<char>(std::to_integer<unsigned char>(b)));
    }

    // 查找头部和正文之间的分隔符
    size_t header_end = data_str.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return response; // 无效的HTTP响应
    }

    // 提取头部
    std::string headers_str = data_str.substr(0, header_end);

    // 解析状态行
    std::smatch match;
    if (std::regex_search(headers_str, match, http_response_regex)) {
        response.status_code = std::stoi(match[1]);
    }

    // 解析头部
    std::istringstream headers_stream(headers_str);
    std::string line;
    std::getline(headers_stream, line); // 跳过状态行

    while (std::getline(headers_stream, line) && !line.empty()) {
        // 移除回车符
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string name = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);

            // 修剪值前面的空白
            value.erase(0, value.find_first_not_of(" \t"));

            response.headers[name] = value;

            // 提取内容类型
            if (name == "Content-Type") {
                response.content_type = value;
                // 提取不带参数的MIME类型
                size_t semicolon_pos = response.content_type.find(';');
                if (semicolon_pos != std::string::npos) {
                    response.content_type =
                            response.content_type.substr(0, semicolon_pos);
                }
            }
        }
    }

    // 提取正文
    size_t body_start = header_end + 4; // 跳过\r\n\r\n
    if (body_start < data.size()) {
        response.body.assign(data.begin() + body_start, data.end());
    }

    // 生成文件名
    std::string extension = determine_file_extension(response.content_type, response.body, response.url);
    response.filename =
            "response_" +
            std::to_string(
                std::chrono::system_clock::now().time_since_epoch().count()) +
            extension;

    return response;
}

// 在FilterModule中添加文件类型签名检测（参考Suricata的magic模块）
std::string FilterModule::detect_by_magic_numbers(const std::vector<std::byte> &data) {
    if (data.size() >= 4) {
        // 常见文件类型检测
        const std::byte *header = data.data();

        // PNG
        if (header[0] == std::byte{0x89} && header[1] == std::byte{0x50} &&
            header[2] == std::byte{0x4E} && header[3] == std::byte{0x47})
            return "image/png";

        // JPEG
        if (header[0] == std::byte{0xFF} && header[1] == std::byte{0xD8})
            return "image/jpeg";

        // GIF
        if (header[0] == std::byte{0x47} && header[1] == std::byte{0x49} &&
            header[2] == std::byte{0x46} && header[3] == std::byte{0x38})
            return "image/gif";

        // PDF
        if (header[0] == std::byte{0x25} && header[1] == std::byte{0x50} &&
            header[2] == std::byte{0x44} && header[3] == std::byte{0x46})
            return "application/pdf";

        // ZIP
        if (header[0] == std::byte{0x50} && header[1] == std::byte{0x4B} &&
            header[2] == std::byte{0x03} && header[3] == std::byte{0x04})
            return "application/zip";
        // gif
        if (data.size() >= 3) {
            // GIF87a/GIF89a
            if (header[0] == std::byte{0x47} &&
                header[1] == std::byte{0x49} &&
                header[2] == std::byte{0x46})
                return "image/gif";
        }
        //mpeg
        if (data.size() >= 15) {
            // MPEG audio（MP3）
            if ((header[0] == std::byte{0xFF} && (header[1] & std::byte{0xE0}) == std::byte{0xE0}) ||
                (header[0] == std::byte{0x49} && header[1] == std::byte{0x44} && header[2] == std::byte{0x33}))
                return "audio/mpeg";
        }
    }
    return "application/octet-stream"; // 默认未知类型
}

std::string FilterModule::determine_file_extension(
    const std::string &content_type,
    const std::vector<std::byte> &data,
    const std::string &url) {
    // 将内容类型映射到文件扩展名
    static const std::map<std::string, std::string> extensions = {
        {"text/html", ".html"},
        {"text/plain", ".txt"},
        {"text/css", ".css"},
        {"text/javascript", ".js"},
        {"application/javascript", ".js"},
        {"application/json", ".json"},
        {"image/jpeg", ".jpg"},
        {"image/png", ".png"},
        {"image/gif", ".gif"},
        {"image/svg+xml", ".svg"},
        {"image/webp", ".webp"},
        {"audio/mpeg", ".mp3"},
        {"audio/wav", ".wav"},
        {"video/mp4", ".mp4"},
        {"video/webm", ".webm"},
        {"application/pdf", ".pdf"},
        {"application/zip", ".zip"},
        {"application/x-www-form-urlencoded", ".form"}
    };

    // 优先级1：基于Content-Type的扩展名
    if (!content_type.empty()) {
        auto it = extensions.find(content_type);
        if (it != extensions.end()) return it->second;
    }

    // 优先级2：基于魔数的扩展名检测
    std::string magic_type = detect_by_magic_numbers(data);
    if (magic_type != "application/octet-stream") {
        auto it = extensions.find(magic_type);
        if (it != extensions.end()) return it->second;
    }

    // 优先级3：基于URL路径的扩展名猜测（如/download/file.exe）
    size_t last_dot = url.find_last_of('.');
    if (last_dot != std::string::npos) {
        std::string ext = url.substr(last_dot);
        if (ext.size() <= 5) {
            // 限制扩展名长度
            return ext;
        }
    }

    return ".bin"; // 最终默认值
}

// =========== 保存模块实现 ===========
bool SaveModule::initialize() {
    try {
        ensure_directory_exists(output_dir);
        return true;
    } catch (const std::exception &e) {
        std::cerr << "保存模块初始化错误: " << e.what() << std::endl;
        return false;
    }
}

void SaveModule::ensure_directory_exists(const std::string &dir) {
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }
}

std::string SaveModule::sanitize_filename(const std::string &filename) {
    std::string result = filename;
    // 替换无效文件名字符
    const std::string invalid_chars = "\\/:*?\"<>|";
    for (char c: invalid_chars) {
        std::replace(result.begin(), result.end(), c, '_');
    }
    return result;
}

bool SaveModule::save_response(const HttpResponse &response) {
    std::lock_guard<std::mutex> lock(save_mutex);

    try {
        // 创建内容类型特定的子目录
        std::string subdir = output_dir;
        if (response.content_type.find("text/html") == 0) {
            subdir += "/html";
        } else if (response.content_type.find("image/") == 0) {
            subdir += "/images";
        } else if (response.content_type.find("video/") == 0) {
            subdir += "/videos";
        } else if (response.content_type.find("audio/") == 0) {
            subdir += "/audio";
        } else {
            subdir += "/other";
        }

        ensure_directory_exists(subdir);

        // 净化文件名
        std::string safe_filename = sanitize_filename(response.filename);
        std::string filepath = subdir + "/" + safe_filename;

        // 保存文件
        std::ofstream file(filepath, std::ios::binary);
        if (!file) {
            std::cerr << "打开文件写入错误: " << filepath << std::endl;
            return false;
        }

        // 将std::byte数据写入文件
        for (const auto &b: response.body) {
            file.put(static_cast<char>(std::to_integer<unsigned char>(b)));
        }

        if (!file) {
            std::cerr << "写入文件错误: " << filepath << std::endl;
            return false;
        }

        return true;
    } catch (const std::exception &e) {
        std::cerr << "保存响应错误: " << e.what() << std::endl;
        return false;
    }
}

// =========== 主函数 ===========
int main(int argc, char *argv[]) {
    std::string interface = "enp1s0"; // 默认接口
    std::string output_dir = "./http_output"; // 默认输出目录
    std::string filter_expr = "tcp port 80 or tcp port 443"; // 默认过滤器

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (arg == "-f" && i + 1 < argc) {
            filter_expr = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "用法: " << argv[0]
                    << " [-i 接口] [-o 输出目录] [-f 过滤表达式]" << std::endl;
            std::cout << "  -i  要抓取的网络接口 (默认: eth0)" << std::endl;
            std::cout << "  -o  保存文件的输出目录 (默认: ./http_output)"
                    << std::endl;
            std::cout << "  -f  PCAP过滤表达式 (默认: tcp port 80 or tcp port 443)"
                    << std::endl;
            return 0;
        }
    }

    try {
        ControlModule control(interface, output_dir, filter_expr);
        control.initialize();

        std::cout << "流量分析还原程序" << std::endl;
        std::cout << "==================" << std::endl;
        control.status();
        std::cout << "按回车键开始抓包..." << std::endl;
        std::cin.get();

        control.start();

        std::cout << "按回车键停止抓包..." << std::endl;
        std::cin.get();

        control.stop();
    } catch (const std::exception &e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
