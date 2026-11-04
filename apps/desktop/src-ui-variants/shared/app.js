// FCP 客户端界面逻辑（5 个样式方案共用）。
//
// 同一份代码跑两种宿主：
//   1. Tauri 里：window.__TAURI__ 存在 -> invoke/listen 走 Rust 壳；
//   2. 浏览器里直接打开 index.html（挑样式用）：没有 __TAURI__ -> 走内置
//      模拟器，自己造 stats 和日志行，界面照样动起来。
// 这样换样式只改 index.html / CSS，一个字的逻辑都不用重写。
"use strict";

const TAURI = window.__TAURI__ || null;
const invoke = TAURI ? TAURI.core.invoke : demoInvoke;
const listen = TAURI ? TAURI.event.listen : demoListen;

const READY_PREFIXES = ["client: socks5/http on", "running:"];

const $ = (id) => document.getElementById(id);
const FIELDS = ["host", "port", "key", "listen", "listenPort", "mtu", "budget", "k", "remember"];
const LS_KEY = "fcp.client.settings";
const LS_SECRET = "fcp.client.secret";

let running = false;
let startedAt = 0;
let lastT = 0;
let lastTx = 0;
let lastRx = 0;

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
  const s = Math.floor(sec);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  const pad = (v) => String(v).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(r)}` : `${pad(m)}:${pad(r)}`;
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

function setRunning(state, hint) {
  running = state;
  $("start").disabled = state;
  $("stop").disabled = !state;
  for (const id of FIELDS) {
    const el = $(id);
    if (el) el.disabled = state;
  }
  if ($("keyToggle")) $("keyToggle").disabled = state;
  const dot = $("dot");
  if (dot) dot.className = "dot" + (state ? " on" : "");
  if (hint !== undefined && $("hint")) $("hint").textContent = hint;
  if (!state && $("uptime")) $("uptime").textContent = "--";
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
    for (const id of FIELDS) {
      if (id === "remember" || saved[id] === undefined) continue;
      const el = $(id);
      if (el) el.value = saved[id];
    }
  }
  if ($("remember") && $("remember").checked) {
    const secret = localStorage.getItem(LS_SECRET);
    if (secret) $("key").value = secret;
  }
}

function saveSettings() {
  if (!$("remember").checked) {
    localStorage.removeItem(LS_KEY);
    localStorage.removeItem(LS_SECRET);
    return;
  }
  const saved = {};
  for (const id of FIELDS) {
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
  const mtu = Number($("mtu").value);
  const k = Number($("k").value);
  const budget = Number($("budget").value);
  const key = $("key").value.trim();
  if (!/^[0-9a-fA-F]{32}$/.test(key)) return { err: "预共享密钥必须是 32 位十六进制" };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { err: "UDP 端口无效" };
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) return { err: "本地端口无效" };
  if (!Number.isInteger(mtu) || mtu < 576 || mtu > 9000) return { err: "MTU 应在 576..9000" };
  if (!Number.isInteger(k) || k < -1 || k > 7) return { err: "k 应在 -1..7" };
  if (!(budget >= 0 && budget <= 1)) return { err: "FEC 预算应在 0..1" };
  return {
    cfg: {
      host: $("host").value.trim(),
      port,
      keyHex: key,
      listen: $("listen").value.trim(),
      listenPort,
      mtu,
      k,
      fecBudget: budget,
      trace: "",
    },
  };
}

async function onStart() {
  const { cfg, err } = collect();
  if (err) {
    $("hint").textContent = err;
    return;
  }
  if (!cfg.host) {
    $("hint").textContent = "服务器地址不能为空";
    return;
  }
  $("hint").textContent = "启动中…";
  try {
    await invoke("start_proxy", { cfg });
    saveSettings();
    startedAt = performance.now();
    lastT = lastTx = lastRx = 0;
    $("hint").textContent = `本地代理 ${cfg.listen}:${cfg.listenPort} → ${cfg.host}:${cfg.port}`;
    setRunning(true);
  } catch (e) {
    $("hint").textContent = String(e);
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
  setRunning(false, "已停止");
}

function onStats(s) {
  const bytes = (k) => Number(s[k] || 0);
  if ($("m-t")) $("m-t").textContent = s.t.toFixed(1) + " s";
  if ($("uptime")) $("uptime").textContent = running ? fmtUptime(s.t) : "--";
  if ($("m-live")) $("m-live").textContent = bytes("live");
  if ($("m-est")) $("m-est").textContent = bytes("up");
  if ($("m-tun")) $("m-tun").textContent = bytes("tunnels");
  if ($("m-tx")) $("m-tx").textContent = fmtBytes(bytes("tx"));
  if ($("m-rx")) $("m-rx").textContent = fmtBytes(bytes("rx"));

  const dt = s.t - lastT;
  if (dt > 0.2) {
    if ($("m-tx")) $("m-tx").title = fmtRate((bytes("tx") - lastTx) / dt);
    if ($("m-rx")) $("m-rx").title = fmtRate((bytes("rx") - lastRx) / dt);
    lastT = s.t;
    lastTx = bytes("tx");
    lastRx = bytes("rx");
  }

  // 诊断计数：只展示非零项，避免一排 0 噪声。
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
      const v = bytes(k);
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
  }

  // 给需要画图/画环的样式（V5、V4）留钩子。
  document.dispatchEvent(new CustomEvent("fcp:stats", { detail: s }));
}

function boot() {
  loadSettings();
  setRunning(false, "");
  $("start").addEventListener("click", onStart);
  $("stop").addEventListener("click", onStop);
  if ($("clear")) $("clear").addEventListener("click", () => $("log").replaceChildren());
  if ($("keyToggle")) {
    $("keyToggle").addEventListener("click", () => {
      const k = $("key");
      const show = k.type === "password";
      k.type = show ? "text" : "password";
      $("keyToggle").textContent = show ? "隐藏" : "显示";
    });
  }
  for (const id of FIELDS) {
    const el = $(id);
    if (el) el.addEventListener("change", saveSettings);
  }

  listen("proxy-stats", (e) => onStats(e.payload));
  listen("proxy-log", (e) => {
    const { stream, line } = e.payload;
    if (stream === "out" && READY_PREFIXES.some((p) => line.startsWith(p))) {
      logLine(line, "out");
    } else {
      logLine(line, stream === "err" ? "err" : "out");
    }
  });
  listen("proxy-state", (e) => {
    const p = e.payload;
    if (p.state === "idle") {
      const code = p.code;
      setRunning(false, code === 0 || code === null ? "已停止" : `代理异常退出（code ${code}）`);
      if ($("dot")) $("dot").className = "dot" + (code === 0 || code === null ? "" : " bad");
    }
  });

  invoke("proxy_status")
    .then((s) => {
      if (s === "running") {
        startedAt = performance.now();
        setRunning(true, "代理运行中");
      }
    })
    .catch(() => {});

  if (!TAURI) {
    const tag = document.getElementById("demo-tag");
    if (tag) tag.hidden = false;
  }
}

// ---------------------------------------------------------------- 浏览器模拟器
// 只在没有 Tauri 宿主时启用；纯粹为了选样式时界面不是一块死板。

const demo = { handlers: {}, timer: null, t: 0, tx: 0, rx: 0, stats: {} };

function demoEmit(name, payload) {
  const h = demo.handlers[name];
  if (h) h({ payload });
}

function demoListen(name, cb) {
  demo.handlers[name] = cb;
  return Promise.resolve(() => delete demo.handlers[name]);
}

async function demoInvoke(cmd) {
  if (cmd === "proxy_status") return "idle";
  if (cmd === "start_proxy") {
    if (demo.timer) throw new Error("代理已在运行");
    demo.t = 0;
    demo.tx = 0;
    demo.rx = 0;
    demo.stats = {};
    demoEmit("proxy-log", { stream: "out", line: "client: socks5/http on 127.0.0.1:1080 -> fcp 198.51.100.7:4460" });
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
  const txAdd = Math.round(40000 + Math.random() * 160000);
  const rxAdd = Math.round(60000 + Math.random() * 260000);
  demo.tx += txAdd;
  demo.rx += rxAdd;
  const s = {
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
  };
  demoEmit("proxy-stats", s);
  if (Math.random() < 0.35) {
    const [stream, line] = DEMO_LINES[Math.floor(Math.random() * DEMO_LINES.length)];
    demoEmit("proxy-log", { stream, line });
  }
}

window.addEventListener("DOMContentLoaded", boot);
