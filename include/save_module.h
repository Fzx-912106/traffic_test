#ifndef SAVE_MODULE_H
#define SAVE_MODULE_H

#include "packet.h"
#include <filesystem>
#include <mutex>

class SaveModule {
private:
    std::string output_dir;
    std::mutex save_mutex;

    void ensure_directory_exists(const std::string &dir);

    std::string sanitize_filename(const std::string &filename);

public:
    SaveModule(const std::string &dir);

    bool initialize();

    bool save_response(const HttpResponse &response);
};

#endif // SAVE_MODULE_H

//// =========== 保存模块 ===========
//class SaveModule {
//private:
//    std::string output_dir;
//    std::mutex save_mutex;
//
//    void ensure_directory_exists(const std::string &dir);
//
//    std::string sanitize_filename(const std::string &filename);
//
//public:
//    SaveModule(const std::string &dir) : output_dir(dir) {
//    }
//
//    bool initialize();
//
//    bool save_response(const HttpResponse &response);
//};
