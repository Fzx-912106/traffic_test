#ifndef CAPTURE_MODULE_H
#define CAPTURE_MODULE_H

#include "packet.h"

#include <pcap.h>
#include <thread>
#include <mutex>
#include <vector>

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
    CaptureModule(const std::string &iface, const std::string &filter);

    ~CaptureModule();

    bool initialize();

    void start();

    void stop();

    std::vector<Packet> get_packets();
};

#endif // CAPTURE_MODULE_H


// =========== 抓包模块 ===========
//class CaptureModule {
//private:
//    pcap_t *handle{nullptr};
//    std::string interface;
//    std::string filter_expr;
//    std::atomic<bool> running{false};
//    std::thread capture_thread;
//    std::mutex packet_mutex;
//    std::vector<Packet> packet_buffer;
//
//    static void packet_handler(u_char *user_data,
//                               const struct pcap_pkthdr *pkthdr,
//                               const u_char *packet);
//
//    void capture_thread_func();
//
//public:
//    CaptureModule(const std::string &iface, const std::string &filter)
//        : interface(iface), filter_expr(filter) {
//    }
//
//    ~CaptureModule();
//
//    bool initialize();
//
//    void start();
//
//    void stop();
//
//    std::vector<Packet> get_packets();
//};
