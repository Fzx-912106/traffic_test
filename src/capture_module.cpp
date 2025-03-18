// =========== 抓包模块实现 ===========
#include "../include/capture_module.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>

CaptureModule::CaptureModule(const std::string &iface, const std::string &filter)
    : interface(iface), filter_expr(filter) {}

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
