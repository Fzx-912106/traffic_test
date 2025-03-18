#ifndef CONTROL_MODULE_H
#define CONTROL_MODULE_H

#include "packet.h"
#include "capture_module.h"
#include "filter_module.h"
#include "save_module.h"

#include <memory>
#include <atomic>

// class CaptureModule;
// class FilterModule;
// class SaveModule;

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
                  const std::string &filter);

    void initialize();

    void start();

    void stop();

    void status() const;
};

#endif // CONTROL_MODULE_H


//// =========== 控制模块 ===========
//class ControlModule {
//private:
//    std::shared_ptr<CaptureModule> capture_module;
//    std::shared_ptr<FilterModule> filter_module;
//    std::shared_ptr<SaveModule> save_module;
//    std::atomic<bool> running{false};
//    std::string interface;
//    std::string output_dir;
//    std::string filter_expr;
//
//public:
//    ControlModule(const std::string &iface, const std::string &output,
//                  const std::string &filter)
//        : interface(iface), output_dir(output), filter_expr(filter) {
//    }
//
//    void initialize();
//
//    void start();
//
//    void stop();
//
//    void status() const;
//};
