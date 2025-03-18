#include "../include/save_module.h"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

// =========== 保存模块实现 ===========
SaveModule::SaveModule(const std::string &dir) : output_dir(dir){}

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
