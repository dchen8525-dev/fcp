// FCP 客户端界面逻辑（浅色主题 5 版共用）。
//
// 参数策略：主界面只留 4 项——服务器地址、UDP 端口、预共享密钥、本地代理端口。
// MTU / FEC 上限 / 固定 k / 监听地址 / trace 全塞进「高级」，不展开时用
// sidecar 自己的缺省值补齐（cli.cc 的 flag 默认），语义和显式传一样。
//
// 同一份代码跑两种宿主：Tauri 里走 invoke/listen；浏览器里（挑样式）走内置
// 模拟器，界面上点「启动」就有假的 stats 和日志在跑。?autostart=1 用于截图。
"use strict";

const TAURI = window.__TAURI__ || null;
const invoke = TAURI ? TAURI.core.invoke : demoInvoke;
const listen = TAURI ? TAURI.event.listen : demoListen;

const READY_PREFIXES = ["client: socks5/http on", "running:"];
const LS_KEY = "fcp.client.settings";
const LS_SECRET = "fcp.client.secret";

const SIMPLE = ["host", "port", "key", "listenPort"];
const ADVANCED = ["listen", "mtu", "budget", "k", "trace"];
const ALL = SIMPLE.concat(ADVANCED, ["remember"]);
// 测速面板的输入不属于连接配置：运行中也要能改，所以单独列出（持久化但不随
// setRunning 禁用）。
const SPEED = ["speedSeconds"];
const PERSIST = ALL.concat(SPEED);

// sidecar 的缺省值（apps/cli/cli.cc 的 flag 默认）。
const DEFAULTS = { listen: "127.0.0.1", mtu: 1400, k: -1, budget: 0.5, trace: "" };

const $ = (id) => document.getElementById(id);

let running = false;
let advanced = false;
let lastT = 0;
let lastTx = 0;
let lastRx = 0;
let speedRunning = false;
// 测速的丢包率随 done 事件一起回来（测速进程自己的 FEC 统计），代理 stats 里
// 的 loss_*_n 与它无关：测速根本不经过代理会话。
const speedLoss = { inPpm: 0, inN: 0, outPpm: 0, outN: 0 };

const isAdvOpen = () => {
  const body = $("advBody");
  return !!body && !body.hidden;
};

function fmtBytes(n) {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + " GiB";
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(2) + " MiB";
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KiB";
  return n + " B";
}

function fmtRate(bps) {
  if (bps >= 1 << 20) return (bps / (1 << 20)).toFixed(2) + " MiB/s";
  if (bps >= 1 << 10) return (bps / (1 << 10)).toFixed(0) + " KiB/s";
  return bps.toFixed(0) + " B/s";
}

function fmtUptime(sec) {
  const s = Math.max(0, Math.floor(sec));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  const p = (v) => String(v).padStart(2, "0");
  return h > 0 ? `${h}:${p(m)}:${p(r)}` : `${p(m)}:${p(r)}`;
}

function logLine(text, cls) {
  const el = $("log");
  if (!el) return;
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 4;
  const span = document.createElement("span");
  if (cls) span.className = cls;
  span.textContent = text + "\n";
  el.appendChild(span);
  while (el.childElementCount > 4000) el.removeChild(el.firstElementChild);
  if (atBottom) el.scrollTop = el.scrollHeight;
}

// 密钥行内校验：够 32 位十六进制才点亮对勾，省得点了启动才报错。
function paintKeyState() {
  const el = $("keyState");
  if (!el) return;
  const v = $("key").value.trim();
  const ok = /^[0-9a-fA-F]{32}$/.test(v);
  el.textContent = !v ? "" : ok ? "✓ 32 位" : `${v.length}/32`;
  el.className = "key-state" + (!v ? "" : ok ? " ok" : " bad");
}

function setAdvanced(open, persist = true) {
  advanced = open;
  const body = $("advBody");
  if (body) body.hidden = !open;
  const btn = $("advToggle");
  if (btn) {
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    const label = btn.querySelector("[data-label]");
    if (label) label.textContent = open ? "收起高级" : "高级设置";
  }
  if (persist) saveSettings();
}

function setRunning(state, hint) {
  running = state;
  if ($("start")) $("start").disabled = state;
  if ($("stop")) $("stop").disabled = !state;
  for (const id of ALL) {
    const el = $(id);
    if (el) el.disabled = state;
  }
  if ($("keyToggle")) $("keyToggle").disabled = state;
  if ($("advToggle")) $("advToggle").disabled = state;
  const dot = $("dot");
  if (dot) dot.className = "dot" + (state ? " on" : "");
  // 测速走独立的 fcp-client 进程，不依赖代理会话，所以空闲时也能点。
  if ($("speedStart")) $("speedStart").disabled = speedRunning;
  if ($("speedHint") && !speedRunning) {
    $("speedHint").textContent = state ? "约 2 × 单程时长" : "服务端需以 --speedtest 启动";
  }
  if (hint !== undefined && $("hint")) $("hint").textContent = hint;
  if (!state && $("uptime")) $("uptime").textContent = "--";
  document.body.classList.toggle("is-running", state);
  document.dispatchEvent(new CustomEvent("fcp:state", { detail: { running: state } }));
}

function loadSettings() {
  let saved = null;
  try {
    saved = JSON.parse(localStorage.getItem(LS_KEY) || "null");
  } catch (_) {
    saved = null;
  }
  if (saved) {
    for (const id of PERSIST) {
      if (id === "remember" || saved[id] === undefined) continue;
      const el = $(id);
      if (el) el.value = saved[id];
    }
  }
  setAdvanced(saved ? !!saved.advanced : false, false);
  if ($("remember") && $("remember").checked) {
    const secret = localStorage.getItem(LS_SECRET);
    if (secret) $("key").value = secret;
  }
  paintKeyState();
}

function saveSettings() {
  if (!$("remember") || !$("remember").checked) {
    localStorage.removeItem(LS_KEY);
    localStorage.removeItem(LS_SECRET);
    return;
  }
  const saved = { advanced };
  for (const id of PERSIST) {
    if (id === "remember" || id === "key") continue;
    const el = $(id);
    if (el) saved[id] = el.value;
  }
  localStorage.setItem(LS_KEY, JSON.stringify(saved));
  localStorage.setItem(LS_SECRET, $("key").value);
}

function collect() {
  const port = Number($("port").value);
  const listenPort = Number($("listenPort").value);
  const key = $("key").value.trim();
  if (!/^[0-9a-fA-F]{32}$/.test(key)) return { err: "预共享密钥要 32 位十六进制" };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { err: "UDP 端口无效" };
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) return { err: "本地端口无效" };

  const open = isAdvOpen();
  const pick = (id) => {
    const el = $(id);
    if (!open || !el) return DEFAULTS[id];
    return el.value;
  };

  const mtu = Number(pick("mtu"));
  if (!Number.isInteger(mtu) || mtu < 576 || mtu > 9000) return { err: "MTU 应在 576..9000" };
  const k = Number(pick("k"));
  if (!Number.isInteger(k) || k < -1 || k > 7) return { err: "k 应在 -1..7" };
  const fecBudget = Number(pick("budget"));
  if (!(fecBudget >= 0 && fecBudget <= 1)) return { err: "FEC 预算应在 0..1" };
  const listenAddr = String(pick("listen")).trim();
  if (!listenAddr) return { err: "本地监听地址不能为空" };
  const trace = String(pick("trace") || "").trim();

  return {
    cfg: {
      host: $("host").value.trim(),
      port,
      keyHex: key,
      listen: listenAddr,
      listenPort,
      mtu,
      k,
      fecBudget,
      trace,
    },
  };
}

async function onStart() {
  if (running) return;
  const { cfg, err } = collect();
  if (err) {
    if ($("hint")) $("hint").textContent = err;
    return;
  }
  if (!cfg.host) {
    if ($("hint")) $("hint").textContent = "服务器地址不能为空";
    return;
  }
  if ($("hint")) $("hint").textContent = "正在连接…";
  try {
    await invoke("start_proxy", { cfg });
    saveSettings();
    lastT = lastTx = lastRx = 0;
    if ($("hint")) $("hint").textContent = `本地代理 ${cfg.listen}:${cfg.listenPort} → ${cfg.host}:${cfg.port}`;
    setRunning(true);
  } catch (e) {
    if ($("hint")) $("hint").textContent = String(e);
    logLine("start failed: " + e, "err");
    setRunning(false);
  }
}

async function onStop() {
  try {
    await invoke("stop_proxy");
  } catch (e) {
    logLine("stop failed: " + e, "err");
  }
  setRunning(false, "已断开");
}

function speedHint(text, bad) {
  const el = $("speedHint");
  if (!el) return;
  el.textContent = text;
  el.classList.toggle("error", !!bad);
}

async function onSpeedStart() {
  if (speedRunning) return;
  const seconds = Number($("speedSeconds").value);
  if (!Number.isInteger(seconds) || seconds < 3 || seconds > 30) {
    speedHint("时长应在 3..30 秒", true);
    return;
  }
  const { cfg, err } = collect();
  if (err) {
    speedHint(err, true);
    return;
  }
  if (!cfg.host) {
    speedHint("服务器地址不能为空", true);
    return;
  }

  speedRunning = true;
  speedLoss.inPpm = speedLoss.inN = speedLoss.outPpm = speedLoss.outN = 0;
  paintSpeedLoss();
  if ($("speedStart")) $("speedStart").disabled = true;
  if ($("sp-down")) $("sp-down").textContent = "--";
  if ($("sp-up")) $("sp-up").textContent = "--";
  if ($("sp-down-sub")) $("sp-down-sub").textContent = "下行…";
  if ($("sp-up-sub")) $("sp-up-sub").textContent = "排队中";
  if ($("sp-progress")) $("sp-progress").style.width = "0%";
  speedHint(`测速中… 下行 ${seconds}s + 上行 ${seconds}s`);

  try {
    saveSettings();
    // 帧层裸测速：第二个 fcp-client 直连服务端的 UDP 端口，不经代理会话。
    await invoke("start_speedtest", {
      cfg: { host: cfg.host, port: cfg.port, keyHex: cfg.keyHex, seconds, mtu: cfg.mtu },
    });
  } catch (e) {
    speedRunning = false;
    if ($("speedStart")) $("speedStart").disabled = false;
    speedHint(String(e), true);
  }
}

function paintSpeedLoss() {
  const pct = (ppm, n) => (n > 0 ? (ppm / 10000).toFixed(2) + "%" : "--");
  const set = (id, v) => { if ($(id)) $(id).textContent = v; };
  set("sp-loss-in", pct(speedLoss.inPpm, speedLoss.inN));
  set("sp-loss-in-n", speedLoss.inN > 0 ? `n=${speedLoss.inN}` : "");
  set("sp-loss-out", pct(speedLoss.outPpm, speedLoss.outN));
  set("sp-loss-out-n", speedLoss.outN > 0 ? `n=${speedLoss.outN}` : "");
}

function onStats(s) {
  const num = (k) => Number(s[k] || 0);
  const set = (id, v) => {
    const el = $(id);
    if (el) el.textContent = v;
  };
  set("m-t", s.t.toFixed(1) + " s");
  set("uptime", running ? fmtUptime(s.t) : "--");
  set("m-live", num("live"));
  set("m-est", num("up"));
  set("m-tun", num("tunnels"));
  set("m-tx", fmtBytes(num("tx")));
  set("m-rx", fmtBytes(num("rx")));

  const dt = s.t - lastT;
  let txRate = 0;
  let rxRate = 0;
  if (dt > 0.2) {
    txRate = (num("tx") - lastTx) / dt;
    rxRate = (num("rx") - lastRx) / dt;
    if ($("m-tx")) $("m-tx").title = fmtRate(txRate);
    if ($("m-rx")) $("m-rx").title = fmtRate(rxRate);
    lastT = s.t;
    lastTx = num("tx");
    lastRx = num("rx");
  }

  const diag = [
    ["bad_entry", "坏入口"],
    ["refused", "拒绝"],
    ["hs_failed", "握手失败"],
    ["reset", "重置"],
    ["idle", "空闲回收"],
    ["clash", "salt 冲突"],
    ["over", "超会话"],
    ["bad_cfg", "错配置"],
    ["no_entropy", "无熵"],
    ["budget", "限速建连"],
    ["unknown", "未知 salt"],
  ];
  const host = $("diag");
  if (host) {
    host.replaceChildren();
    for (const [k, name] of diag) {
      const v = num(k);
      if (!v) continue;
      const d = document.createElement("div");
      d.className = "metric";
      const cap = document.createElement("span");
      cap.className = "cap";
      cap.textContent = name;
      const b = document.createElement("b");
      b.textContent = String(v);
      d.append(cap, b);
      host.appendChild(d);
    }
    host.hidden = !host.childElementCount;
  }

  document.dispatchEvent(
    new CustomEvent("fcp:stats", { detail: Object.assign({}, s, { txRate, rxRate }) })
  );
}

function boot() {
  loadSettings();
  setRunning(false, "");
  if ($("start")) $("start").addEventListener("click", onStart);
  if ($("stop")) $("stop").addEventListener("click", onStop);
  if ($("speedStart")) $("speedStart").addEventListener("click", onSpeedStart);
  if ($("clear")) $("clear").addEventListener("click", () => $("log").replaceChildren());
  if ($("keyToggle")) {
    $("keyToggle").addEventListener("click", () => {
      const k = $("key");
      const show = k.type === "password";
      k.type = show ? "text" : "password";
      const label = $("keyToggle").querySelector("[data-label]");
      if (label) label.textContent = show ? "隐藏" : "显示";
      else $("keyToggle").textContent = show ? "隐藏" : "显示";
    });
  }
  if ($("advToggle")) {
    $("advToggle").addEventListener("click", () => setAdvanced(!isAdvOpen()));
  }
  if ($("key")) $("key").addEventListener("input", paintKeyState);
  for (const id of PERSIST) {
    const el = $(id);
    if (el) el.addEventListener("change", saveSettings);
  }

  listen("proxy-stats", (e) => onStats(e.payload));
  listen("speedtest-progress", (e) => {
    if (!speedRunning) return;
    const p = e.payload || {};
    const up = p.direction === "up";
    const secs = Number(p.elapsedMs || 0) / 1000;
    const bytes = Number(p.bytes || 0);
    const total = Math.max(3, Number($("speedSeconds").value) || 8);
    if ($("sp-progress")) {
      const base = up ? 50 : 0;
      $("sp-progress").style.width = Math.min(99, base + (secs / total) * 50) + "%";
    }
    const sub = $(up ? "sp-up-sub" : "sp-down-sub");
    if (sub) sub.textContent = `${fmtBytes(bytes)} / ${secs.toFixed(1)}s`;
  });
  listen("speedtest-done", (e) => {
    // 上一轮迟到的 done 可能落在新的一轮里；只认当前这一轮。
    if (!speedRunning) return;
    const r = e.payload || {};
    speedRunning = false;
    if ($("speedStart")) $("speedStart").disabled = false;
    const fill = (sample, id, subId) => {
      if ($(subId)) $(subId).classList.remove("bad");
      if (!sample) {
        if ($(id)) $(id).textContent = "--";
        if ($(subId)) $(subId).textContent = "未完成";
        return;
      }
      if ($(id)) $(id).textContent = Number(sample.mbps || 0).toFixed(2);
      const secs = Number(sample.seconds || 0);
      const lossy = sample.acked === false;
      const ack = lossy
        ? `（${fmtBytes(Number(sample.lostBytes || 0))} 未到达）`
        : "";
      if ($(subId)) {
        $(subId).textContent = `${fmtBytes(Number(sample.bytes || 0))} / ${secs.toFixed(1)}s${ack}`;
        $(subId).classList.toggle("bad", lossy);
      }
    };
    fill(r.download, "sp-down", "sp-down-sub");
    fill(r.upload, "sp-up", "sp-up-sub");
    if ($("sp-progress")) $("sp-progress").style.width = "100%";
    // 丢包随测速结果一起回来（帧层口径，测速进程自己统计），不再从代理 stats 采：
    // 测速不经过代理会话，代理侧那时本来也没有流量。
    const loss = (sample) => {
      if (!sample || !(Number(sample.lossN || 0) > 0)) return null;
      return { ppm: Number(sample.lossPpm || 0), n: Number(sample.lossN) };
    };
    const dl = loss(r.download);
    const ul = loss(r.upload);
    if (dl) { speedLoss.inPpm = dl.ppm; speedLoss.inN = dl.n; }
    if (ul) { speedLoss.outPpm = ul.ppm; speedLoss.outN = ul.n; }
    paintSpeedLoss();
    if (r.error) speedHint(String(r.error), true);
    else speedHint("测速完成");
  });
  listen("proxy-log", (e) => {
    const { stream, line } = e.payload;
    if (stream === "out" && READY_PREFIXES.some((p) => line.startsWith(p))) logLine(line, "out");
    else logLine(line, stream === "err" ? "err" : "out");
  });
  listen("proxy-state", (e) => {
    const p = e.payload;
    if (p.state === "idle") {
      const code = p.code;
      setRunning(false, code === 0 || code === null ? "已断开" : `代理异常退出（code ${code}）`);
      if ($("dot")) $("dot").className = "dot" + (code === 0 || code === null ? "" : " bad");
    }
  });

  invoke("proxy_status")
    .then((s) => {
      if (s === "running") setRunning(true, "代理运行中");
    })
    .catch(() => {});

  if (!TAURI) {
    const tag = document.querySelector("[data-demo]");
    if (tag) tag.hidden = false;
  }
  const q = new URLSearchParams(location.search);
  if (q.get("autostart") === "1") {
    setTimeout(() => {
      $("host").value = "198.51.100.7";
      $("key").value = "0123456789abcdef0123456789abcdef";
      paintKeyState();
      onStart();
    }, 40);
  }
}

// ---------------------------------------------------------------- 浏览器模拟器
const demo = { handlers: {}, timer: null, t: 0, tx: 0, rx: 0 };

function demoEmit(name, payload) {
  const h = demo.handlers[name];
  if (h) h({ payload });
}

function demoListen(name, cb) {
  demo.handlers[name] = cb;
  return Promise.resolve(() => delete demo.handlers[name]);
}

async function demoInvoke(cmd, args) {
  if (cmd === "proxy_status") return "idle";
  if (cmd === "start_speedtest") {
    // 浏览器挑样式时给一个可看的假测速，免得面板永远停在“测速中”。
    const seconds = Number(args && args.cfg ? args.cfg.seconds : 8);
    let t = 0;
    const timer = setInterval(() => {
      t += 0.5;
      const down = t <= seconds;
      const bytes = Math.round((down ? 9.5 : 3.2) * 125000 * Math.min(t, seconds));
      demoEmit("speedtest-progress", {
        direction: down ? "down" : "up",
        bytes,
        elapsedMs: Math.round((down ? t : t - seconds) * 1000),
      });
      if (t >= seconds * 2) {
        clearInterval(timer);
        demoEmit("speedtest-done", {
          seconds,
          download: { mbps: 76.0, bytes: 76000000, seconds, acked: true, lossPpm: 4200, lossN: 12345 },
          upload: { mbps: 25.6, bytes: 25600000, seconds, acked: true, lossPpm: 900, lossN: 12345 },
          error: null,
        });
      }
    }, 500);
    return null;
  }
  if (cmd === "start_proxy") {
    if (demo.timer) throw new Error("代理已在运行");
    demo.t = demo.tx = demo.rx = 0;
    demoEmit("proxy-log", {
      stream: "out",
      line: "client: socks5/http on 127.0.0.1:1080 -> fcp 198.51.100.7:4460",
    });
    demo.timer = setInterval(demoTick, 500);
    return null;
  }
  if (cmd === "stop_proxy") {
    if (demo.timer) {
      clearInterval(demo.timer);
      demo.timer = null;
      demoEmit("proxy-log", { stream: "out", line: "stop: 收到停止信号，正在回收会话" });
      demoEmit("proxy-state", { state: "idle", code: 0 });
    }
    return null;
  }
  return null;
}

const DEMO_LINES = [
  ["out", "tunnel: 新建会话 id=0x7f3a peer=10.0.0.14:51820"],
  ["out", "fec: k=2 m=3 budget=0.50 自适应收敛"],
  ["out", "tunnel: 会话 id=0x7f3a 空闲回收（无数据 30s）"],
  ["err", "reassembly: 丢包重排超时，等待 FEC 补齐"],
  ["out", "kcp: rtt=42ms rto=120ms cwnd=24"],
  ["out", "tunnel: 新建会话 id=0x2c19 peer=10.0.0.22:51820"],
];

function demoTick() {
  demo.t += 0.5;
  demo.tx += Math.round(40000 + Math.random() * 160000);
  demo.rx += Math.round(60000 + Math.random() * 260000);
  demoEmit("proxy-stats", {
    t: demo.t,
    live: 2 + Math.round(Math.random() * 3),
    up: 14 + Math.round(demo.t / 30),
    tunnels: 40 + Math.round(demo.t / 12),
    tx: demo.tx,
    rx: demo.rx,
    bad_entry: 0,
    refused: 0,
    hs_failed: Math.random() < 0.03 ? 1 : 0,
    reset: Math.random() < 0.05 ? 1 : 0,
    idle: Math.round(demo.t / 20),
    clash: 0,
    over: 0,
    bad_cfg: 0,
    no_entropy: 0,
    budget: Math.random() < 0.04 ? 1 : 0,
    unknown: 0,
  });
  if (Math.random() < 0.35) {
    const [stream, line] = DEMO_LINES[Math.floor(Math.random() * DEMO_LINES.length)];
    demoEmit("proxy-log", { stream, line });
  }
}

window.addEventListener("DOMContentLoaded", boot);
