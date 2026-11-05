// FCP 单文件引导器（C++/Win32；仅有的第三方代码是 miniz/ 里的 zip 读取）。
//
// 发行物布局（scripts/desktop/bundle_windows_portable.ps1 拼装）：
//
//   [本 exe][LZMA1 载荷（内层是 zip）][80 字节尾部]
//
// 尾部（小端）：
//
//   0..8    "FCPBOOT2"
//   8..12   u32 格式版本（当前为 2）
//   12..16  u32 编码（1 = LZMA1_alone：5 字节 props + 8 字节原长 + 流）
//   16..24  u64 载荷偏移
//   24..32  u64 载荷长度（压缩态）
//   32..40  u64 解压后长度（内层 zip 的 store 长度）
//   40..72  SHA-256（对压缩态载荷；打包器算好写进尾部，本程序只透传 ——
//           缓存目录名用它，不自己算哈希）
//   72..80  保留（0）
//
// 内层 zip 以 store（不压缩）写入再整体 LZMA：两次压缩叠在同一段字节上
// 只会互相干扰，实测 LZMA 比 zip 的 deflate 小约 27%。
//
// 首次运行把载荷解到 %LOCALAPPDATA%\FCP\bin\<SHA-256 前 8 字节十六进制>\，
// 之后直接启动缓存里的 FCP.exe；不同版本按内容哈希分目录共存，7 天未用的
// 旧目录清理。用户配置由 Qt 的 QSettings 存注册表（HKCU\Software\FCP\FCP
// Client），与本缓存无关，升级不丢。
//
// 行为对齐已退役的 Rust 版（决策 #75：彻底无 Rust，单文件形态保留）：
// 解压目录名、.ready/.used 标记、.tmp-<key>-<pid> 半成品目录、7 天/1 小时
// 清理阈值、自检报告文件、错误日志路径全部一致；CI 的
// --fcp-launcher-selftest 冒烟不改。

#include <windows.h>
#include <shlobj.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include "lzma/LzmaDec.h"
#include "miniz/miniz.h"

namespace {

constexpr uint64_t kFooterLen = 80;
constexpr char kMagic[8] = {'F', 'C', 'P', 'B', 'O', 'O', 'T', '2'};
constexpr uint32_t kFormatVersion = 2;
constexpr uint32_t kCodecLzma1 = 1;
// LZMA1_alone 头：1 字节属性 + 4 字节字典大小 + 8 字节原长。
constexpr size_t kLzmaAloneHeader = 13;
// 解压总量护栏：本发行物的 Qt 目录树 ~40 MiB 未压缩，留一个量级余量。
// 它拦"被篡改发行物里的解压炸弹"；路径越界由 SafeEntryName 把守。
constexpr uint64_t kMaxUncompressedTotal = 1ull << 30;  // 1 GiB
constexpr uint64_t kMaxEntryCount = 8192;

constexpr wchar_t kAppName[] = L"FCP.exe";
constexpr wchar_t kSidecarName[] = L"fcp-client.exe";
constexpr wchar_t kReadyMarker[] = L".ready";
constexpr wchar_t kUsedStamp[] = L".used";
constexpr wchar_t kSelftestFlag[] = L"--fcp-launcher-selftest";
// FILETIME 百纳秒：7 天 / 1 小时（.tmp- 半成品，别打断正在解压的实例）。
constexpr int64_t kCacheRetention100ns = 7ll * 24 * 60 * 60 * 10000000;
constexpr int64_t kTmpRetention100ns = 60ll * 60 * 10000000;

// ---------- 小工具 ----------

std::string HexLower(const uint8_t* bytes, size_t n) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    out.push_back(kHex[bytes[i] >> 4]);
    out.push_back(kHex[bytes[i] & 0xF]);
  }
  return out;
}

std::wstring Utf8ToWide(const char* s) {
  if (s == nullptr) return std::wstring();
  const int need = ::MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
  if (need <= 0) return std::wstring();
  std::wstring out(static_cast<size_t>(need - 1), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), need);
  return out;
}

std::string WideToNarrow(const std::wstring& w) {
  if (w.empty()) return std::string();
  const int need = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                         static_cast<int>(w.size()), nullptr,
                                         0, nullptr, nullptr);
  if (need <= 0) return std::string();
  std::string out(static_cast<size_t>(need), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        out.data(), need, nullptr, nullptr);
  return out;
}

std::wstring ErrorText(DWORD err) {
  wchar_t* msg = nullptr;
  const DWORD n = ::FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
  std::wstring out;
  if (n != 0 && msg != nullptr) {
    out.assign(msg, n);
    while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n'))
      out.pop_back();
  }
  if (msg != nullptr) ::LocalFree(msg);
  if (out.empty()) out = L"错误 " + std::to_wstring(err);
  return out;
}

bool FileExists(const std::wstring& path) {
  const DWORD attrs = ::GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES &&
         (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool DirExists(const std::wstring& path) {
  const DWORD attrs = ::GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES &&
         (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

FILETIME NowFiletime() {
  FILETIME ft{};
  ::GetSystemTimeAsFileTime(&ft);
  return ft;
}

int64_t FiletimeToI64(const FILETIME& ft) {
  return (static_cast<int64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// 年龄只用于清理阈值：系统时钟回拨只会让清理更保守，负差值截到 0。
int64_t FiletimeAge100ns(const FILETIME& older) {
  const int64_t d = FiletimeToI64(NowFiletime()) - FiletimeToI64(older);
  return d > 0 ? d : 0;
}

bool ReadFull(HANDLE file, void* buf, size_t want) {
  uint8_t* cursor = static_cast<uint8_t*>(buf);
  while (want != 0) {
    const DWORD chunk = want > 0x40000000u ? 0x40000000u : static_cast<DWORD>(want);
    DWORD got = 0;
    if (!::ReadFile(file, cursor, chunk, &got, nullptr) || got == 0)
      return false;
    cursor += got;
    want -= got;
  }
  return true;
}

bool WriteFileNarrow(const std::wstring& path, const std::string& text,
                     bool append) {
  HANDLE h = ::CreateFileW(
      path.c_str(), append ? FILE_APPEND_DATA : GENERIC_WRITE, 0, nullptr,
      append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  DWORD wrote = 0;
  ::WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &wrote, nullptr);
  ::CloseHandle(h);
  return true;
}

// ---------- 路径 ----------

// %LOCALAPPDATA% 一般都在；SHGetFolderPath 失败时退化到 TEMP，
// 让自检/日志至少有地方落盘。
std::wstring FcpRoot() {
  wchar_t base[MAX_PATH] = {};
  if (::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr,
                         SHGFP_TYPE_CURRENT, base) != S_OK) {
    ::GetTempPathW(MAX_PATH, base);
  }
  std::wstring root = base;
  while (!root.empty() && (root.back() == L'\\' || root.back() == L'/'))
    root.pop_back();
  return root + L"\\FCP";
}

std::wstring FcpCacheRoot() { return FcpRoot() + L"\\bin"; }
std::wstring SelftestFile() { return FcpRoot() + L"\\selftest.txt"; }
std::wstring LaunchLog() { return FcpRoot() + L"\\launcher.log"; }

// ---------- 尾部 ----------

struct Footer {
  uint64_t offset = 0;
  uint64_t len = 0;    // 压缩态长度
  uint64_t usize = 0;  // 解压后（内层 zip）长度
  uint8_t sha256[32] = {};
};

uint32_t ReadU32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadU64(const uint8_t* p) {
  uint64_t v = 0;
  for (int b = 7; b >= 0; --b) v = (v << 8) | p[b];
  return v;
}

// error 只在返回 false 时被赋值。
bool ParseFooter(const uint8_t* buf, uint64_t total, Footer* out,
                 std::wstring* error) {
  if (std::memcmp(buf, kMagic, sizeof(kMagic)) != 0) {
    *error = L"不是 FCP 单文件发行物：缺少引导尾部标记（文件可能被截断）";
    return false;
  }
  const uint32_t format = ReadU32(buf + 8);
  if (format != kFormatVersion) {
    *error = L"不支持的引导格式版本 " + std::to_wstring(format) +
             L"，请重新下载发行物";
    return false;
  }
  if (ReadU32(buf + 12) != kCodecLzma1) {
    *error = L"不支持的载荷编码（需要重新下载发行物）";
    return false;
  }
  const uint64_t offset = ReadU64(buf + 16);
  const uint64_t len = ReadU64(buf + 24);
  const uint64_t usize = ReadU64(buf + 32);
  // 不接受空载荷；offset+len 必须正好指到尾部开头。
  if (len == 0 || usize == 0 || offset > total - kFooterLen ||
      offset + len != total - kFooterLen) {
    *error = L"引导尾部与载荷长度不一致（文件被截断或拼接错误）";
    return false;
  }
  if (usize > kMaxUncompressedTotal) {
    *error = L"引导尾部声明了异常的解压体积";
    return false;
  }
  std::memcpy(out->sha256, buf + 40, 32);
  out->offset = offset;
  out->len = len;
  out->usize = usize;
  return true;
}

// ---------- 解压 ----------

// 逐级 CreateDirectory，已存在不是错误。
bool MkDirs(const std::wstring& path) {
  std::wstring cur;
  for (size_t at = 0; at <= path.size(); ++at) {
    if (at == path.size() || path[at] == L'\\' || path[at] == L'/') {
      if (!cur.empty() && cur.back() != L':') {
        if (!::CreateDirectoryW(cur.c_str(), nullptr) && !DirExists(cur))
          return false;
      }
      if (at != path.size()) cur.push_back(path[at]);
    } else {
      cur.push_back(path[at]);
    }
  }
  return true;
}

// zip 条目名安全门（对应 Rust 版 enclosed_name）：拒绝盘符、UNC、`..` 段。
// 两种分隔符都当段界，比 Rust 版更保守。
bool SafeEntryName(const char* utf8, std::wstring* out) {
  const std::wstring wide = Utf8ToWide(utf8);
  if (wide.empty()) return false;
  if (wide.size() >= 2 && wide[1] == L':') return false;
  if (wide.rfind(L"\\\\", 0) == 0) return false;
  std::wstring joined;
  size_t start = 0;
  bool first = true;
  for (size_t i = 0; i <= wide.size(); ++i) {
    if (i != wide.size() && wide[i] != L'/' && wide[i] != L'\\') continue;
    const std::wstring part = wide.substr(start, i - start);
    start = i + 1;
    if (part.empty() || part == L".") continue;
    if (part == L"..") return false;
    if (!first) joined.push_back(L'\\');
    joined += part;
    first = false;
  }
  if (joined.empty()) return false;
  *out = joined;
  return true;
}

// LZMA SDK 的分配器接口：解压时的概率模型缓冲区。
void* LzmaAlloc(ISzAllocPtr, size_t size) { return std::malloc(size); }
void LzmaFree(ISzAllocPtr, void* address) { std::free(address); }
const ISzAlloc kLzmaAlloc = {LzmaAlloc, LzmaFree};

bool ExtractPayload(HANDLE archive, const Footer& footer,
                    const std::wstring& dest, std::wstring* error) {
  // 64 位下尾部里的长度一定装得进 size_t（发行物压缩态 ~9 MiB、解压后
  // ~40 MiB；真被篡改成大值由 ParseFooter 的护栏与 bad_alloc 兜住）。
  const LARGE_INTEGER at{.LowPart = static_cast<DWORD>(footer.offset),
                         .HighPart = static_cast<LONG>(footer.offset >> 32)};
  if (!::SetFilePointerEx(archive, at, nullptr, FILE_BEGIN)) {
    *error = L"无法定位载荷：" + ErrorText(::GetLastError());
    return false;
  }
  // 整段载荷一次读入（压缩态）。
  std::vector<uint8_t> packed(static_cast<size_t>(footer.len));
  if (!ReadFull(archive, packed.data(), packed.size())) {
    *error = L"无法读取载荷：" + ErrorText(::GetLastError());
    return false;
  }
  if (packed.size() < kLzmaAloneHeader) {
    *error = L"载荷短于 LZMA 头（文件损坏）";
    return false;
  }

  // LZMA1_alone：前 13 字节是属性/字典/原长，LzmaDecode 只吃前 5 字节属性，
  // 压缩流从第 13 字节开始；原长已由尾部给出，按精确长度解。
  std::vector<uint8_t> payload(static_cast<size_t>(footer.usize));
  SizeT dest_len = payload.size();
  SizeT src_len = packed.size() - kLzmaAloneHeader;
  ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
  const SRes res =
      LzmaDecode(payload.data(), &dest_len, packed.data() + kLzmaAloneHeader,
                 &src_len, packed.data(), 5, LZMA_FINISH_END, &status,
                 &kLzmaAlloc);
  if (res != SZ_OK || dest_len != payload.size()) {
    *error = L"载荷解压失败（LZMA 错误 " + std::to_wstring(res) +
             L"，输出 " + std::to_wstring(dest_len) + L" 字节）";
    return false;
  }

  mz_zip_archive zip{};
  if (mz_zip_reader_init_mem(&zip, payload.data(), payload.size(), 0) !=
      MZ_TRUE) {
    *error = L"载荷不是有效的 zip（miniz 错误 " +
             std::to_wstring(mz_zip_get_last_error(&zip)) + L"）";
    return false;
  }
  const mz_uint count = mz_zip_reader_get_num_files(&zip);
  if (count == 0 || count > kMaxEntryCount) {
    mz_zip_reader_end(&zip);
    *error = L"载荷条目数异常（" + std::to_wstring(count) + L"）";
    return false;
  }

  bool ok = true;
  uint64_t written_total = 0;
  for (mz_uint index = 0; index < count; ++index) {
    mz_zip_archive_file_stat stat{};
    if (!mz_zip_reader_file_stat(&zip, index, &stat)) {
      *error = L"读取载荷条目 " + std::to_wstring(index) + L" 失败";
      ok = false;
      break;
    }
    std::wstring rel;
    if (!SafeEntryName(stat.m_filename, &rel)) {
      *error = std::wstring(L"载荷条目路径非法：") + Utf8ToWide(stat.m_filename);
      ok = false;
      break;
    }
    const std::wstring out = dest + L"\\" + rel;
    // 逐条目 + 累计解压体积护栏。
    if (stat.m_uncomp_size > kMaxUncompressedTotal ||
        written_total + stat.m_uncomp_size > kMaxUncompressedTotal) {
      *error = L"载荷解压体积超出护栏（条目 " + rel + L"）";
      ok = false;
      break;
    }
    if (mz_zip_reader_is_file_a_directory(&zip, index)) {
      if (!MkDirs(out)) {
        *error = L"无法创建目录 " + out;
        ok = false;
        break;
      }
      continue;
    }
    const size_t slash = out.find_last_of(L"\\/");
    if (slash != std::wstring::npos && !MkDirs(out.substr(0, slash))) {
      *error = L"无法创建 " + out.substr(0, slash);
      ok = false;
      break;
    }
    // 打包器 .NET ZipFile 生成的条目名是 ASCII（Qt DLL 与本工程文件名的
    // 英文子集），miniz 窄字符 fopen 直接可用；非 ASCII 条目名不属于本
    // 发行物。缺 WideToNarrow 语义时 miniz 的 zip 层以原地 fopen 打开。
    if (!mz_zip_reader_extract_to_file(&zip, index, WideToNarrow(out).c_str(),
                                       0)) {
      *error = L"解压 " + rel + L" 失败（磁盘满或路径被占用）";
      ok = false;
      break;
    }
    written_total += stat.m_uncomp_size;
  }
  mz_zip_reader_end(&zip);
  return ok;
}

// ---------- 缓存 ----------

bool CacheDirReady(const std::wstring& dir) {
  return FileExists(dir + L"\\" + kAppName) &&
         FileExists(dir + L"\\" + kSidecarName) &&
         FileExists(dir + L"\\" + kReadyMarker);
}

// cache exe 被运行中的进程以共享读打开，独占写打开失败就是"有人持有"。
// 文件缺失返回 false —— 空壳目录照样删。
bool CacheInUse(const std::wstring& dir) {
  const std::wstring exe = dir + L"\\" + kAppName;
  if (!FileExists(exe)) return false;
  HANDLE h = ::CreateFileW(exe.c_str(), GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return true;
  ::CloseHandle(h);
  return false;
}

bool TouchUsed(const std::wstring& dir) {
  // 内容无意义（Rust 版写秒级时间戳），mtime 才是清理的依据。
  return WriteFileNarrow(dir + L"\\" + kUsedStamp, "used", false);
}

bool DeleteTree(const std::wstring& path) {
  std::vector<wchar_t> from(path.begin(), path.end());
  from.push_back(L'\0');
  from.push_back(L'\0');  // SHFileOperation 吃双 NUL 结尾的串表
  SHFILEOPSTRUCTW op{};
  op.wFunc = FO_DELETE;
  op.pFrom = from.data();
  op.fFlags = FOF_NO_UI | FOF_SILENT;
  return ::SHFileOperationW(&op) == 0;
}

void CleanupOld(const std::wstring& current_dir) {
  const std::wstring root = FcpCacheRoot();
  WIN32_FIND_DATAW data{};
  HANDLE find = ::FindFirstFileW((root + L"\\*").c_str(), &data);
  if (find == INVALID_HANDLE_VALUE) return;
  do {
    if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
    const std::wstring name = data.cFileName;
    if (name == L"." || name == L"..") continue;
    const std::wstring dir = root + L"\\" + name;
    if (_wcsicmp(dir.c_str(), current_dir.c_str()) == 0) continue;

    const bool is_tmp = name.rfind(L".tmp-", 0) == 0;
    // .tmp 看目录自身 mtime；版本目录优先看 .used 的 mtime（每次启动
    // CREATE_ALWAYS 重写，mtime 即最近一次使用），缺 stamp 用目录 mtime
    // 兜底 —— 与 Rust 版读 stamp 内容语义一致。
    FILETIME mtime = data.ftLastWriteTime;
    if (!is_tmp) {
      WIN32_FILE_ATTRIBUTE_DATA fa{};
      if (::GetFileAttributesExW((dir + L"\\" + kUsedStamp).c_str(),
                                 GetFileExInfoStandard, &fa)) {
        mtime = fa.ftLastWriteTime;
      }
    }
    if (FiletimeAge100ns(mtime) <=
        (is_tmp ? kTmpRetention100ns : kCacheRetention100ns))
      continue;
    if (CacheInUse(dir)) continue;  // 留到下次清理
    DeleteTree(dir);
  } while (::FindNextFileW(find, &data));
  ::FindClose(find);
}

// 备守：EnsurePayload 里任何提前退出的路径都由它把临时目录删干净
// （对应 Rust 版 TmpGuard 的 Drop）。
struct TmpGuard {
  std::wstring dir;
  bool keep = false;
  explicit TmpGuard(std::wstring d) : dir(std::move(d)) {}
  ~TmpGuard() {
    if (!keep) DeleteTree(dir);
  }
  TmpGuard(const TmpGuard&) = delete;
  TmpGuard& operator=(const TmpGuard&) = delete;
};

bool EnsurePayload(HANDLE archive, const Footer& footer, std::wstring* dir_out,
                   std::wstring* error) {
  const std::wstring root = FcpCacheRoot();
  const std::string key_narrow = HexLower(footer.sha256, 8).substr(0, 16);
  const std::wstring key = Utf8ToWide(key_narrow.c_str());
  const std::wstring dir = root + L"\\" + key;
  if (CacheDirReady(dir)) {
    TouchUsed(dir);
    *dir_out = dir;
    return true;
  }
  if (!MkDirs(root)) {
    *error = L"无法创建缓存目录 " + root + L"：" + ErrorText(::GetLastError());
    return false;
  }
  // 上次可能留下半截目录（没有 .ready），先清掉。
  if (DirExists(dir)) DeleteTree(dir);

  const std::wstring tmp =
      root + L"\\.tmp-" + key + L"-" + std::to_wstring(::GetCurrentProcessId());
  DeleteTree(tmp);
  if (!MkDirs(tmp)) {
    *error = L"无法创建临时目录 " + tmp + L"：" + ErrorText(::GetLastError());
    return false;
  }
  TmpGuard guard(tmp);
  if (!ExtractPayload(archive, footer, tmp, error)) return false;

  if (!FileExists(tmp + L"\\" + kAppName) ||
      !FileExists(tmp + L"\\" + kSidecarName)) {
    *error = std::wstring(L"载荷里缺少 ") +
             (FileExists(tmp + L"\\" + kAppName) ? kSidecarName : kAppName);
    return false;
  }
  if (!WriteFileNarrow(tmp + L"\\" + kReadyMarker, key_narrow, false)) {
    *error = L"无法写入缓存标记：" + ErrorText(::GetLastError());
    return false;
  }

  // 目录改名是原子的：另一实例已放好同名目录时，直接用它的。
  if (!::MoveFileExW(tmp.c_str(), dir.c_str(), MOVEFILE_WRITE_THROUGH) &&
      !CacheDirReady(dir)) {
    *error = L"无法把解压结果放到 " + dir + L"（可能被占用：" +
             ErrorText(::GetLastError()) + L"）";
    return false;  // guard 收尾删 tmp
  }
  guard.keep = true;  // 成功：tmp 已改名（或被另一个实例收走）
  TouchUsed(dir);
  *dir_out = dir;
  return true;
}

// ---------- 报告/启动 ----------

void AppendLaunchLog(const std::wstring& message) {
  MkDirs(FcpRoot());
  HANDLE h = ::CreateFileW(LaunchLog().c_str(), FILE_APPEND_DATA, 0, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return;
  // 一行：[秒级 Unix 时间] 消息（UTF-8），对齐 Rust 版。
  std::string line =
      "[" + std::to_string(::GetTickCount64() / 1000) + "] " +
      WideToNarrow(message) + "\n";
  DWORD wrote = 0;
  ::WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
  ::CloseHandle(h);
}

void ReportError(const std::wstring& message) {
  AppendLaunchLog(message);
  const std::wstring text = L"FCP 启动失败\r\n\r\n" + message;
  ::MessageBoxW(nullptr, text.c_str(), L"FCP", MB_OK | MB_ICONERROR);
}

bool LaunchApp(const std::wstring& dir, const wchar_t* cmd_tail) {
  std::wstring cmd = L"\"" + dir + L"\\" + kAppName + L"\"";
  if (cmd_tail != nullptr && cmd_tail[0] != L'\0') {
    cmd += L" ";
    cmd += cmd_tail;
  }
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  // cwd = 缓存目录：sidecar 解析按"主程序同目录"找 fcp-client.exe。
  // CREATE_NO_WINDOW 只是不让某些环境闪控制台，GUI 程序本身无控制台。
  const bool ok = ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr, dir.c_str(), &si,
                                   &pi);
  if (ok) {
    ::CloseHandle(pi.hProcess);
    ::CloseHandle(pi.hThread);
  }
  return ok;
}

}  // namespace

int RunMain(int argc, wchar_t** argv) {
  std::wstring tail;
  bool selftest = false;
  for (int i = 1; i < argc; ++i) {
    if (::wcscmp(argv[i], kSelftestFlag) == 0) {
      selftest = true;
      continue;
    }
    if (!tail.empty()) tail.push_back(L' ');
    // 带空格的参数需要再包一层引号（简单粗暴，防"参数里带空格"）。
    const bool needs_quote =
        argv[i][0] != L'\0' && ::wcspbrk(argv[i], L" ") != nullptr;
    if (needs_quote) tail.push_back(L'"');
    tail += argv[i];
    if (needs_quote) tail.push_back(L'"');
  }

  wchar_t self_path[MAX_PATH] = {};
  if (::GetModuleFileNameW(nullptr, self_path, MAX_PATH) == 0) {
    ReportError(L"无法定位自身路径");
    return 1;
  }
  HANDLE archive = ::CreateFileW(self_path, GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
  if (archive == INVALID_HANDLE_VALUE) {
    ReportError(L"无法打开自身：" + ErrorText(::GetLastError()));
    return 1;
  }
  LARGE_INTEGER size{};
  if (!::GetFileSizeEx(archive, &size) || size.QuadPart < 0) {
    ReportError(L"无法读取自身大小：" + ErrorText(::GetLastError()));
    ::CloseHandle(archive);
    return 1;
  }
  const uint64_t total = static_cast<uint64_t>(size.QuadPart);

  std::wstring error;
  std::wstring dir;
  Footer footer;
  if (total < kFooterLen) {
    error = L"不是 FCP 单文件发行物：文件太短";
  } else {
    uint8_t buf[kFooterLen];
    LARGE_INTEGER at{};
    at.QuadPart = static_cast<LONGLONG>(total - kFooterLen);
    if (!::SetFilePointerEx(archive, at, nullptr, FILE_BEGIN) ||
        !ReadFull(archive, buf, kFooterLen)) {
      error = L"无法读取引导尾部：" + ErrorText(::GetLastError());
    } else if (!ParseFooter(buf, total, &footer, &error)) {
      // error 已在 ParseFooter 里填好
    }
  }
  if (error.empty() && !EnsurePayload(archive, footer, &dir, &error)) {
    // error 已填好
  }
  ::CloseHandle(archive);
  if (!error.empty()) {
    ReportError(error);
    return 1;
  }
  CleanupOld(dir);

  if (selftest) {
    // CI 冒烟：报告写到 %LOCALAPPDATA%\FCP\selftest.txt（版本目录是 hex
    // 键 + FCP 根目录，ASCII 转换无损；GUI 子系统下 stdout 不可用）。
    MkDirs(FcpRoot());
    for (const wchar_t* name : {kAppName, kSidecarName}) {
      if (!FileExists(dir + L"\\" + name)) {
        WriteFileNarrow(SelftestFile(),
                        "failed: cache missing " + WideToNarrow(name) + "\n",
                        false);
        ReportError(std::wstring(L"自检失败：缓存里缺少 ") + name);
        return 1;
      }
    }
    WriteFileNarrow(SelftestFile(), "ok\ncache=" + WideToNarrow(dir) + "\n",
                    false);
    return 0;
  }

  if (!LaunchApp(dir, tail.empty() ? nullptr : tail.c_str())) {
    ReportError(L"无法启动 " + dir + L"\\" + kAppName + L"：" +
                ErrorText(::GetLastError()));
    return 1;
  }
  return 0;
}

int wmain(int argc, wchar_t** argv) {
  // 载荷读入与解压里有按内容大小的分配；发行物被篡改成超大长度时它们的
  // 失败形态是异常而不是返回值，在这里兜住并走统一的报告/日志出口。
  try {
    return RunMain(argc, argv);
  } catch (const std::exception& e) {
    ReportError(Utf8ToWide(e.what()));
    return 1;
  } catch (...) {
    ReportError(L"内部错误：未知异常（内存分配失败或发行物损坏）");
    return 1;
  }
}
