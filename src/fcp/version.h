// FCP 协议版本（fcp::kVersionMajor）。线上常量统一起版 1，不与发布版本挂钩。

#ifndef FCP_VERSION_H_
#define FCP_VERSION_H_

namespace fcp {

inline constexpr int kVersionMajor = 1;

// 发布版本（仓库根 VERSION 文件）。由 CMake 以 FCP_PRODUCT_VERSION 注入：
// 库自身编进 fcp 的消费者（CLI 两个可执行文件用 --version 打印它）。
#ifndef FCP_PRODUCT_VERSION
#define FCP_PRODUCT_VERSION "0.0.0-dev"
#endif

inline constexpr const char* kProductVersion = FCP_PRODUCT_VERSION;

}  // namespace fcp

#endif  // FCP_VERSION_H_
