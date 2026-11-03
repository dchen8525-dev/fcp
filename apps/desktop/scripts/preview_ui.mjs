// 预览 / 截图 5 版界面。
//
//   node scripts/preview_ui.mjs            # 起本地预览服务，按回车出链接
//   node scripts/preview_ui.mjs --shots    # 用无头 Chrome 给每版截图到 dist/ui-shots/
//
// 浏览器里打开时 app.js 走内置模拟器：点"启动代理"会有假的 stats/日志在跑，
// 方便只看样式不连真服务器。真实链路在 Tauri 里跑（同样这几份 index.html）。
import { createServer } from "node:http";
import { readFile, readdir, mkdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { extname, join, resolve, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const VARIANTS = resolve(ROOT, "src-ui-variants");
const SHOTS = resolve(ROOT, "../../dist/ui-shots");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

async function variants() {
  const names = (await readdir(VARIANTS, { withFileTypes: true }))
    .filter((d) => d.isDirectory() && d.name !== "shared")
    .map((d) => d.name)
    .sort();
  return names;
}

// 共享脚本由每版自己在 </body> 前引用（app.js / app-light.js）。
// 共享脚本引用改到 /shared/，其余原样。
async function page(dir) {
  const html = await readFile(join(VARIANTS, dir, "index.html"), "utf8");
  return html.replace(/src="((?:tokens|app[\w-]*)\.js)"/g, 'src="/shared/$1"');
}

function serve(port = 0) {
  return new Promise((ok) => {
    const srv = createServer(async (req, res) => {
      try {
        const url = new URL(req.url, "http://x");
        let p = decodeURIComponent(url.pathname);
        if (p === "/" || p === "") {
          const list = await variants();
          res.writeHead(200, { "content-type": MIME[".html"] });
          res.end(indexPage(list));
          return;
        }
        const m = p.match(/^\/v\/([^/]+)\/?$/);
        if (m) {
          res.writeHead(200, { "content-type": MIME[".html"] });
          res.end(await page(m[1]));
          return;
        }
        // 共享脚本（tokens.js、app.js、app-light.js …）一律按文件名取。
        const shared = p.match(/^\/shared\/([\w.-]+\.js)$/);
        if (shared) {
          res.writeHead(200, { "content-type": MIME[".js"] });
          res.end(await readFile(join(VARIANTS, "shared", shared[1])));
          return;
        }
        // 版本目录里的任何静态文件（css/png/svg）原样给。
        const asset = p.match(/^\/v\/([^/]+)\/([\w.-]+\.(css|png|svg))$/);
        if (asset) {
          res.writeHead(200, { "content-type": MIME[extname(asset[2])] });
          res.end(await readFile(join(VARIANTS, asset[1], asset[2])));
          return;
        }
        res.writeHead(404).end("not found");
      } catch (e) {
        res.writeHead(500).end(String(e));
      }
    });
    srv.listen(port, "127.0.0.1", () => ok(srv));
  });
}

function indexPage(list) {
  const cards = list
    .map(
      (n) => `<a class="c" href="/v/${n}/"><b>${n.replace(/^l(\d)-/, "浅色方案 $1 · ")}</b><span>打开 →</span></a>`
    )
    .join("\n");
  return `<!doctype html><meta charset="utf-8"><title>FCP 界面方案</title>
<style>
body{margin:0;padding:40px;background:#0e1116;color:#e6edf3;font:15px/1.5 system-ui,"Microsoft YaHei UI",sans-serif}
h1{font-size:18px;letter-spacing:.08em;margin:0 0 18px}
a.c{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;margin:10px 0;max-width:560px;
  background:#161c25;border:1px solid #232c39;border-radius:10px;color:#e6edf3;text-decoration:none}
a.c span{color:#4a9eff;font-size:13px}
a.c:hover{border-color:#4a9eff}
p{color:#8b97a8;font-size:13px;max-width:640px}
</style>
<h1>FCP 客户端 · 浅色主题 5 版</h1>
<p>v5 浅色主题上的 5 个优化方向。浏览器里点「启动代理」跑的是模拟数据（假 stats 与日志），
只影响观感；真实链路在 Tauri 壳里跑同一份 index.html。</p>
${cards}`;
}

async function findChrome() {
  const cands = [
    process.env.CHROME,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  for (const c of cands) if (existsSync(c)) return c;
  return null;
}

function run(cmd, args) {
  return new Promise((ok, bad) => {
    const p = spawn(cmd, args, { stdio: "inherit" });
    p.on("exit", (code) => (code === 0 ? ok() : bad(new Error(`${basename(cmd)} exit ${code}`))));
    p.on("error", bad);
  });
}

// 截图走本地服务（file:// 下模块/脚本路径容易踩坑），每版截一张空态 + 一张"运行中"。
async function shots() {
  const chrome = await findChrome();
  if (!chrome) {
    console.error("找不到 Chrome/Edge；设 CHROME=<路径> 再试。");
    process.exit(1);
  }
  const srv = await serve(0);
  const port = srv.address().port;
  await mkdir(SHOTS, { recursive: true });
  const list = await variants();
  for (const v of list) {
    for (const mode of ["idle", "running"]) {
      const out = join(SHOTS, `${v}-${mode}.png`);
      // 默认按 Tauri 窗口尺寸截；SHOT_SIZE=WxH 可换（例如 1024x680 验证小窗）。
      const size = process.env.SHOT_SIZE || "1120x760";
      // 每张图一套独立 profile：共享 profile 会把上次写进 localStorage 的
      // "已启动过一次"之类状态带进来，idle 截图就不再是空态。截完即删。
      const profile = join(SHOTS, `.profile-${v}-${mode}`);
      await run(chrome, [
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-first-run",
        `--user-data-dir=${profile}`,
        "--force-device-scale-factor=1",
        `--window-size=${size}`,
        "--virtual-time-budget=2500",
        `--screenshot=${out}`,
        `http://127.0.0.1:${port}/v/${v}/?autostart=${mode === "running" ? 1 : 0}`,
      ]);
      rm(profile, { recursive: true, force: true }).catch(() => {});
      console.log("shot:", out);
    }
  }
  srv.close();
  await writeFile(
    join(SHOTS, "README.txt"),
    `FCP 浅色主题截图（${new Date().toISOString()}），来源 apps/desktop/src-ui-variants/ 下 l1–l5。\n` +
      `重新生成：cd apps/desktop && node scripts/preview_ui.mjs --shots\n`
  );
}

const args = new Set(process.argv.slice(2));
if (args.has("--shots")) {
  await shots();
} else {
  const srv = await serve(Number(process.env.PORT || 0));
  const port = srv.address().port;
  console.log(`预览地址：http://127.0.0.1:${port}/`);
  for (const v of await variants()) console.log(`  http://127.0.0.1:${port}/v/${v}/`);
  console.log("Ctrl+C 结束。");
}
