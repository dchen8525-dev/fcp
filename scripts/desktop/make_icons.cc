// 生成 Qt 客户端用的图标：窗口/托盘图标 fcp.png 与 Windows 资源 fcp.ico。
// （原 scripts/desktop/make_icons.mjs 去 Node 化，2026-11-05：仓库的工程
//   工具统一 shell/C++；deflate 压缩复用 launcher-cpp 里 vendored 的
//   miniz，零新增依赖。）
//
// 图案与色值与旧 .mjs 完全一致（品牌绿圆角方块 + 白色 F + 白色圆点，
// 界面主色 --accent #0f9d76 同源）。产物进仓库，仅在图标几何变化时
// 重新生成：
//
//   MSVC:   cl /nologo /O2 /std:c++17 /EHsc /utf-8 /I apps/desktop/launcher-cpp/miniz ^
//           scripts/desktop/make_icons.cc apps/desktop/launcher-cpp/miniz/miniz.c ^
//           /Fe:build/make_icons.exe && build\make_icons.exe
//   gcc:    g++ -O2 -std=c++17 -I apps/desktop/launcher-cpp/miniz -x c++ \
//           scripts/desktop/make_icons.cc apps/desktop/launcher-cpp/miniz/miniz.c \
//           -o build/make_icons && build/make_icons
//
// 生成物固定字节序（PNG filter 全 0），同代码重复运行输出一致。

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <utility>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "miniz.h"

namespace {

void Save(const std::string& path, const std::vector<uint8_t>& bytes) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f ||
      std::fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size() ||
      std::fclose(f) != 0) {
    std::fprintf(stderr, "无法写 %s\n", path.c_str());
    std::exit(1);
  }
}

std::string OutDir() {
  // make_icons.cc → scripts/desktop → apps/desktop/assets
  namespace fs = std::filesystem;
  fs::path here = fs::path(__FILE__).parent_path();  // scripts/desktop
  return (here / ".." / ".." / "apps" / "desktop" / "assets").string();
}

// ---------- PNG ----------
uint32_t Crc32(const uint8_t* data, size_t len) {
  static uint32_t table[256];
  static bool ready = false;
  if (!ready) {
    for (uint32_t n = 0; n < 256; ++n) {
      uint32_t c = n;
      for (int k = 0; k < 8; ++k)
        c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
      table[n] = c;
    }
    ready = true;
  }
  uint32_t c = 0xffffffffu;
  for (size_t i = 0; i < len; ++i)
    c = table[(c ^ data[i]) & 0xff] ^ (c >> 8);
  return c ^ 0xffffffffu;
}

void Be32(std::vector<uint8_t>* out, uint32_t v) {
  out->push_back(static_cast<uint8_t>(v >> 24));
  out->push_back(static_cast<uint8_t>(v >> 16));
  out->push_back(static_cast<uint8_t>(v >> 8));
  out->push_back(static_cast<uint8_t>(v));
}

void Chunk(std::vector<uint8_t>* out, const char type[4],
           const std::vector<uint8_t>& body) {
  Be32(out, static_cast<uint32_t>(body.size()));
  std::vector<uint8_t> crc_input;
  crc_input.insert(crc_input.end(), type, type + 4);
  crc_input.insert(crc_input.end(), body.begin(), body.end());
  const uint32_t crc = Crc32(crc_input.data(), crc_input.size());
  out->insert(out->end(), crc_input.begin(), crc_input.end());
  Be32(out, crc);
}

// RGBA 像素采样器：几何按 0..1 比例写死，任意尺寸等比缩放。
using PixelFn = void (*)(int x, int y, int size, uint8_t out[4]);

std::vector<uint8_t> Png(int size, PixelFn pixel) {
  // 每行 1 字节 filter(0) + RGBA。ZIP 流本体是这批 scanline 的 deflate。
  std::vector<uint8_t> raw(static_cast<size_t>(size) * (size * 4 + 1));
  uint8_t* p = raw.data();
  for (int y = 0; y < size; ++y) {
    *p++ = 0;  // filter: none
    for (int x = 0; x < size; ++x) {
      pixel(x, y, size, p);
      p += 4;
    }
  }
  std::vector<uint8_t> z(static_cast<size_t>(mz_compressBound(raw.size())));
  mz_ulong zlen = z.size();
  if (mz_compress2(z.data(), &zlen, raw.data(),
                   static_cast<mz_ulong>(raw.size()), 9) != MZ_OK ||
      zlen <= 0) {
    std::fputs("deflate failed\n", stderr);
    std::exit(1);
  }
  z.resize(static_cast<size_t>(zlen));

  std::vector<uint8_t> png;
  // PNG 签名
  const uint8_t sig[8] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
  png.insert(png.end(), sig, sig + 8);

  // IHDR：宽/高/8bit/RGBA/无交错
  std::vector<uint8_t> ihdr;
  Be32(&ihdr, static_cast<uint32_t>(size));
  Be32(&ihdr, static_cast<uint32_t>(size));
  ihdr.push_back(8);  // bit depth
  ihdr.push_back(6);  // color type RGBA
  ihdr.push_back(0);  // deflate
  ihdr.push_back(0);  // filter
  ihdr.push_back(0);  // no interlace
  Chunk(&png, "IHDR", ihdr);

  // IDAT：mz_compress2（默认 window_bits）输出的就是完整 zlib 流
  // （头 + deflate + adler32），直接当 IDAT 体；raw deflate 需要显式
  // window_bits=-MZ_DEFAULT_WINDOW_BITS，这里不需要。
  const std::vector<uint8_t>& idat = z;
  Chunk(&png, "IDAT", idat);

  // 自检：IDAT 的 zlib 流必须能原样解回 scanline（mz_uncompress 认
  // zlib 壳与 adler32）。包壳错了在这里响亮失败， produces 全透明 PNG。
  std::vector<uint8_t> back(raw.size());
  mz_ulong back_len = back.size();
  if (mz_uncompress(back.data(), &back_len, idat.data(),
                    static_cast<mz_ulong>(idat.size())) != MZ_OK ||
      back_len != raw.size() || back != raw) {
    std::fputs("PNG 自检失败：IDAT 解不回 scanline\n", stderr);
    std::exit(1);
  }
  Chunk(&png, "IEND", {});
  return png;
}

// ---------- 图案 ----------
// 底色取界面主色绿（--accent #0f9d76），F 与旁边的点都用白色：绿底在
// 任务栏/资源管理器里辨识度高，纯白字形在小尺寸下也最清楚。
constexpr uint8_t kBg[3] = {15, 157, 118};
constexpr uint8_t kFg[3] = {255, 255, 255};

bool InRect(double x, double y, double l, double t, double r, double b) {
  return x >= l && x <= r && y >= t && y <= b;
}

bool InRoundRect(double x, double y, double l, double t, double r, double b,
                 double rad) {
  const double cx = std::min(std::max(x, l + rad), r - rad);
  const double cy = std::min(std::max(y, t + rad), b - rad);
  const double dx = x - cx;
  const double dy = y - cy;
  return dx * dx + dy * dy <= rad * rad;
}

// 图标主体：一个粗体的 F + 右下角一个圆点（"F." 的字形）。
bool InGlyphF(double x, double y, double s) {
  const double stem_l = 0.285 * s;
  const double stem_w = 0.115 * s;
  const double top = 0.205 * s;
  const double bottom = 0.795 * s;
  if (InRect(x, y, stem_l, top, stem_l + stem_w, bottom)) return true;
  if (InRect(x, y, stem_l, top, 0.665 * s, top + stem_w)) return true;
  if (InRect(x, y, stem_l, 0.455 * s, 0.575 * s, 0.455 * s + stem_w))
    return true;
  return false;
}

bool InGlyphDot(double x, double y, double s) {
  const double r = 0.082 * s;
  const double cx = 0.745 * s;
  const double cy = 0.795 * s - r;  // 底边与 F 的基线对齐
  const double dx = x - cx;
  const double dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

void Pixel(int xi, int yi, int size, uint8_t out[4]) {
  const double x = xi + 0.5;
  const double y = yi + 0.5;
  const double s = size;
  const double pad = s * 0.06;
  if (!InRoundRect(x, y, pad, pad, s - pad, s - pad, s * 0.22)) {
    out[0] = out[1] = out[2] = 0;
    out[3] = 0;  // 全透明，读作"无像素"
    return;
  }
  const uint8_t* color = kBg;
  if (InGlyphF(x, y, s)) color = kFg;
  else if (InGlyphDot(x, y, s)) color = kFg;
  for (int i = 0; i < 3; ++i) {
    // 轻微的上亮下暗（1.0..1.25，顶部更亮）—— 与旧 .mjs 一致
    const double shade = 1 + 0.25 * (1.0 - y / s);
    int v = static_cast<int>(color[i] * shade);
    if (v > 255) v = 255;
    if (v < 0) v = 0;
    out[i] = static_cast<uint8_t>(v);
  }
  out[3] = 255;
}

// ---------- ICO ----------
// DIB 条目（BMP 形状）：小尺寸必须用 BMP，只有 256 用 PNG。单张 256 PNG
// 的 ICO 在资源管理器的小图标视图/部分外壳路径上会退回默认 exe 图标 ——
// 这是"exe 没有图标"的根因。
std::vector<uint8_t> Dib(int size, PixelFn pixel) {
  std::vector<uint8_t> info(40);
  auto le16 = [&](size_t at, uint16_t v) {
    info[at] = static_cast<uint8_t>(v);
    info[at + 1] = static_cast<uint8_t>(v >> 8);
  };
  auto le32 = [&](size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i)
      info[at + i] = static_cast<uint8_t>(v >> (8 * i));
  };
  std::vector<uint8_t> pixels(static_cast<size_t>(size) * size * 4);
  for (int y = 0; y < size; ++y) {
    for (int x = 0; x < size; ++x) {
      uint8_t rgba[4];
      pixel(x, y, size, rgba);
      // DIB 自下而上、BGRA
      const size_t at =
          (static_cast<size_t>(size - 1 - y) * size + x) * 4;
      pixels[at] = rgba[2];
      pixels[at + 1] = rgba[1];
      pixels[at + 2] = rgba[0];
      pixels[at + 3] = rgba[3];
    }
  }
  const size_t mask_row =
      (((static_cast<size_t>(size) + 7) / 8) + 3) / 4 * 4;
  std::vector<uint8_t> mask(mask_row * static_cast<size_t>(size));
  std::fill(mask.begin(), mask.end(), 0);  // AND 掩码：32bpp 靠 alpha
  le32(0, 40);
  le32(4, static_cast<uint32_t>(size));
  le32(8, static_cast<uint32_t>(size * 2));  // XOR + AND
  le16(12, 1);
  le16(14, 32);
  le32(16, 0);  // BI_RGB
  le32(20, static_cast<uint32_t>(pixels.size() + mask.size()));
  std::vector<uint8_t> out;
  out.reserve(info.size() + pixels.size() + mask.size());
  out.insert(out.end(), info.begin(), info.end());
  out.insert(out.end(), pixels.begin(), pixels.end());
  out.insert(out.end(), mask.begin(), mask.end());
  return out;
}

std::vector<uint8_t> Ico(const std::vector<std::pair<int, std::vector<uint8_t>>>&
                             images) {
  std::vector<uint8_t> out;
  auto le16 = [&](uint16_t v) {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
  };
  auto le32 = [&](uint32_t v) {
    for (int i = 0; i < 4; ++i)
      out.push_back(static_cast<uint8_t>(v >> (8 * i)));
  };
  le16(0);
  le16(1);  // type: icon
  le16(static_cast<uint16_t>(images.size()));
  uint32_t offset = 6 + 16 * static_cast<uint32_t>(images.size());
  for (const auto& im : images) {
    const int s = im.first;
    out.push_back(static_cast<uint8_t>(s >= 256 ? 0 : s));  // 宽（0 = 256）
    out.push_back(static_cast<uint8_t>(s >= 256 ? 0 : s));
    out.push_back(0);
    out.push_back(0);
    le16(1);  // planes
    le16(32);  // bpp
    le32(static_cast<uint32_t>(im.second.size()));
    le32(offset);
    offset += static_cast<uint32_t>(im.second.size());
  }
  for (const auto& im : images)
    out.insert(out.end(), im.second.begin(), im.second.end());
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  // 可选 argv[1] = 输出目录（默认从 __FILE__ 推到 apps/desktop/assets；
  // cl/g++ 传绝对路径时两种场景都成立）。
  const std::string dir = argc > 1 ? argv[1] : OutDir();
  Save(dir + "/fcp.png", Png(512, &Pixel));
  std::vector<std::pair<int, std::vector<uint8_t>>> images;
  for (int s : {16, 32, 48, 64, 128}) images.emplace_back(s, Dib(s, &Pixel));
  images.emplace_back(256, Png(256, &Pixel));
  Save(dir + "/fcp.ico", Ico(images));
  std::printf("icons written to %s\n", dir.c_str());
  return 0;
}
