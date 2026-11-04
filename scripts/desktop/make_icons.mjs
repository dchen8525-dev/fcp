// 生成 Qt 客户端用的图标：窗口/托盘图标 fcp.png 与 Windows 资源 fcp.ico。
// 纯 Node 实现（zlib 内置），不依赖任何图形库，CI 上可直接跑。
//
// 图案：品牌绿圆角方块 + 白色 F + 沙色圆点（与界面主色 #0f9d76、
// --sand #f0b46a 同一套）。只在图标尺寸变化时运行：
//   node scripts/desktop/make_icons.mjs
// 产物进仓库（apps/desktop/assets）。
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "..", "apps", "desktop", "assets");
mkdirSync(outDir, { recursive: true });

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c;
    }
  }
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function png(size, rgbaAt) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  let p = 0;
  for (let y = 0; y < size; y++) {
    raw[p++] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = rgbaAt(x, y, size);
      raw[p++] = r; raw[p++] = g; raw[p++] = b; raw[p++] = a;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// 底色取界面的主色绿（--accent #0f9d76），F 与旁边的点都用白色：
// 绿底在任务栏/资源管理器里辨识度高，纯白字形在小尺寸下也最清楚。
const BG = [15, 157, 118];
const FG = [255, 255, 255];
const DOT = [255, 255, 255];

function inRoundRect(x, y, left, top, right, bottom, r) {
  const cx = Math.min(Math.max(x, left + r), right - r);
  const cy = Math.min(Math.max(y, top + r), bottom - r);
  const dx = x - cx, dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

// 图标主体：一个粗体的 F，右下角一个圆点（"F." 的字形）。
// 全部坐标按 0..1 的比例写在 size 的倍数里，任意尺寸都等比。
function inRect(x, y, l, t, r, b) {
  return x >= l && x <= r && y >= t && y <= b;
}

function inGlyphF(x, y, size) {
  const s = size;
  const stemL = 0.285 * s;
  const stemW = 0.115 * s;
  const stemR = stemL + stemW;
  const top = 0.205 * s;
  const bottom = 0.795 * s;
  const topBarR = 0.665 * s;
  const midT = 0.455 * s;
  const midBarR = 0.575 * s;
  if (inRect(x, y, stemL, top, stemR, bottom)) return true;          // 竖笔
  if (inRect(x, y, stemL, top, topBarR, top + stemW)) return true;   // 上横
  if (inRect(x, y, stemL, midT, midBarR, midT + stemW)) return true; // 中横
  return false;
}

function inGlyphDot(x, y, size) {
  const r = 0.082 * size;
  const cx = 0.745 * size;
  const cy = 0.795 * size - r;  // 底边与 F 的基线对齐
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

function pixel(x, y, size) {
  const pad = size * 0.06;
  const r = size * 0.22;
  if (!inRoundRect(x + 0.5, y + 0.5, pad, pad, size - pad, size - pad, r)) {
    return [0, 0, 0, 0];
  }
  // 轻微上亮下暗
  const shade = 1 + 0.25 * (1 - y / size);
  const bg = BG.map((c) => Math.min(255, Math.round(c * shade)));
  const px = x + 0.5;
  const py = y + 0.5;
  if (inGlyphF(px, py, size)) {
    return [...FG, 255];
  }
  if (inGlyphDot(px, py, size)) {
    return [...DOT, 255];
  }
  return [...bg, 255];
}

// 窗口/托盘/AppImage 图标统一用 512 的 PNG。
writeFileSync(join(outDir, "fcp.png"), png(512, pixel));

// ICO：小尺寸必须用 BMP（DIB）条目，只有 256 用 PNG。
// 单张 256x256 PNG 的 ICO 在资源管理器的小图标视图/部分外壳路径上会退回
// 默认 exe 图标——这是"exe 没有图标"的根因，不是资源没写进去。
function dib(size, rgbaAt) {
  const pixels = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = rgbaAt(x, y, size);
      // DIB 是自下而上、BGRA 顺序
      const o = ((size - 1 - y) * size + x) * 4;
      pixels[o] = b; pixels[o + 1] = g; pixels[o + 2] = r; pixels[o + 3] = a;
    }
  }
  // AND 掩码：32 位图靠 alpha，掩码全 0 即可；每行按 4 字节对齐。
  const maskRow = Math.ceil(Math.ceil(size / 8) / 4) * 4;
  const mask = Buffer.alloc(maskRow * size);
  const info = Buffer.alloc(40);
  info.writeUInt32LE(40, 0);            // biSize
  info.writeInt32LE(size, 4);           // biWidth
  info.writeInt32LE(size * 2, 8);       // biHeight（XOR + AND）
  info.writeUInt16LE(1, 12);            // biPlanes
  info.writeUInt16LE(32, 14);           // biBitCount
  info.writeUInt32LE(0, 16);            // BI_RGB
  info.writeUInt32LE(pixels.length + mask.length, 20); // biSizeImage
  return Buffer.concat([info, pixels, mask]);
}

const icoSizes = [16, 32, 48, 64, 128];
const images = icoSizes.map((s) => ({ s, data: dib(s, pixel) }));
images.push({ s: 256, data: png(256, pixel) }); // 256 用 PNG，体积小且 Vista+ 支持

let dataOffset = 6 + 16 * images.length;
const entries = [];
const blobs = [];
for (const im of images) {
  const entry = Buffer.alloc(16);
  entry[0] = im.s >= 256 ? 0 : im.s; // 0 表示 256
  entry[1] = im.s >= 256 ? 0 : im.s;
  entry[2] = 0;                       // 调色板
  entry[3] = 0;
  entry.writeUInt16LE(1, 4);          // planes
  entry.writeUInt16LE(32, 6);         // bpp
  entry.writeUInt32LE(im.data.length, 8);
  entry.writeUInt32LE(dataOffset, 12);
  dataOffset += im.data.length;
  entries.push(entry);
  blobs.push(im.data);
}
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0);
header.writeUInt16LE(1, 2);           // type: icon
header.writeUInt16LE(images.length, 4);
writeFileSync(join(outDir, "fcp.ico"),
              Buffer.concat([header, ...entries, ...blobs]));

console.log("icons written to", outDir);
