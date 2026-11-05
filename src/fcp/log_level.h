// 日志级别契约（src 与 apps 共用）。
//
// 传输面发日志不走"新参数"：每条行开头带 4 字符标签（[e]/[w]/[i]/[d]），
// 唯一的汇集点（reactor 的 log 行接收器）按标签分级、剥离、过滤——
// 引擎/会话的函数签名保持 std::function<void(const std::string&)>)。
//
// 数值含义：severity 越小越要紧（kOff 最大）；`--log=LEVEL` 是"显示类别 ≥
// LEVEL 的行"：error/warn 行默认级别下都在场，debug 行只在 --log=debug 出现。
#ifndef FCP_LOG_LEVEL_H_
#define FCP_LOG_LEVEL_H_

namespace fcp {

enum class LogLevel : int {
  kDebug = 10,  // 传输面内部流水（fecstat 分析、PMTUD 涨幅帧、OPEN sent）
  kInfo = 20,   // 每条请求撇：dial / tunnel open / established / closed
  kWarn = 30,   // 要运维注意但隧道还活着：握手失败重试、被拒绝、stall
  kError = 40,  // 异常（熵源耗尽、OPEN_ERR、配置坏）
  kOff = 100,   // --log=off：什么也不显示
};

// 生产方的行首标签（4 字节宽，方便 startswith(4)）。
inline constexpr const char* kTagDebug = "[d] ";
inline constexpr const char* kTagInfo = "[i] ";
inline constexpr const char* kTagWarn = "[w] ";
inline constexpr const char* kTagError = "[e] ";

inline int Severity(LogLevel level) { return static_cast<int>(level); }

// 汇集点用：识别行首标签 → severity。无标签（含 [x] 这种非标签开头）→
// kInfo 且返回 false。
inline bool TaggedLine(const std::string& line, int* severity) {
  if (line.size() < 4 || line[0] != '[' || line[2] != ']' || line[3] != ' ') {
    *severity = Severity(LogLevel::kInfo);
    return false;
  }
  switch (line[1]) {
    case 'd': *severity = Severity(LogLevel::kDebug); return true;
    case 'i': *severity = Severity(LogLevel::kInfo);  return true;
    case 'w': *severity = Severity(LogLevel::kWarn);  return true;
    case 'e': *severity = Severity(LogLevel::kError); return true;
    default:  *severity = Severity(LogLevel::kInfo);  return false;
  }
}

// 正文：去 4 字符标签（LineBody("[i] hi") == "hi"）；无标签原样返回。
inline std::string LineBody(const std::string& line) {
  int severity = 0;
  return TaggedLine(line, &severity) ? line.substr(4) : line;
}

// 显示名（stderr 行的 [warn]/[error] 前缀在汇集点自带，正文不再重复渲染）。

}  // namespace fcp

#endif  // FCP_LOG_LEVEL_H_
