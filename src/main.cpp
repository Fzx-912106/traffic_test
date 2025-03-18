// 流量分析还原程序
// 使用C++20特性，捕获、过滤和还原HTTP内容
// 使用std::byte代替uint8_t

#include "../include/control_module.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

// // 前向声明
// class ControlModule;
// class CaptureModule;
// class FilterModule;
// class SaveModule;

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
