// 生成 Tauri 需要的 PNG 图标（32/128/512）与 Windows 的 icon.ico。
// 纯 Node 实现（zlib 内置），不依赖任何图形库，CI 上可直接跑。
//
// 图案：深色圆角方块 + 蓝色双箭头（上行/下行，FEC 隧道的最短印记）。
// 只在图标尺寸变化时运行（`npm run icons`），产物进仓库。
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "src-tauri", "icons");
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

// 底色近黑带一点蓝调；F 走中性冰白，点走品牌蓝——两种颜色分工，
// 点在暗底上也足够跳，但不会和字面抢。
const BG = [13, 17, 24];
const FG = [236, 242, 248];
const DOT = [58, 160, 255];

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

const sizes = [32, 128, 512];
const pngs = {};
for (const s of sizes) {
  const buf = png(s, pixel);
  pngs[s] = buf;
  writeFileSync(join(outDir, s === 512 ? "icon.png" : `${s}x${s}.png`), buf);
}

// ICO：单条目 256x256（PNG 压缩），Windows Vista+ 支持。
const icoSize = 256;
const icoPng = png(icoSize, pixel);
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0);
header.writeUInt16LE(1, 2); // type: icon
header.writeUInt16LE(1, 4); // count
const entry = Buffer.alloc(16);
entry[0] = 0; // width 256
entry[1] = 0; // height 256
entry[2] = 0; // palette
entry[3] = 0;
entry.writeUInt16LE(1, 4);  // planes
entry.writeUInt16LE(32, 6); // bpp
entry.writeUInt32LE(icoPng.length, 8);
entry.writeUInt32LE(6 + 16, 12);
writeFileSync(join(outDir, "icon.ico"), Buffer.concat([header, entry, icoPng]));

console.log("icons written to", outDir);
