// FCP 客户端外壳（Tauri 2）。
//
// 传输面一行没动：真正跑隧道的是同一份 `fcp-client`（apps/cli 的
// reactor CLI，M2 §6 的进程外宿主）。这里只做三件事：
//   1. 用表单参数启动 sidecar，密钥走环境变量（不进 argv，`ps` 看不到）；
//   2. 逐行读 stdout：`stats ...` 解析成计数/速率事件，其余原样进日志面板；
//   3. 关窗/停止时收掉子进程。
//
// sidecar 解析顺序：FCP_PROXY_BIN（开发期覆盖）→ 资源目录（AppImage/安装布局）
// → 主程序同目录（Windows 便携包）。找不到就明确报错，不回落到 PATH 上的同名
// 程序。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use tauri::{AppHandle, Emitter, Manager, State};

struct ProxyProc {
    child: Arc<Mutex<Option<Child>>>,
    run_id: Arc<AtomicU64>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ProxyConfig {
    host: String,
    port: u16,
    key_hex: String,
    listen: String,
    listen_port: u16,
    mtu: u16,
    k: i32,
    fec_budget: f64,
    trace: String,
}

fn sidecar_name() -> &'static str {
    if cfg!(windows) {
        "fcp-client.exe"
    } else {
        "fcp-client"
    }
}

fn resolve_sidecar(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("FCP_PROXY_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("FCP_PROXY_BIN={} 不是文件", p.display()));
    }
    if let Ok(dir) = app.path().resource_dir() {
        let p = dir.join(sidecar_name());
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(sidecar_name());
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err(format!(
        "找不到 {}（应与主程序同目录，或用 FCP_PROXY_BIN 指定）",
        sidecar_name()
    ))
}

fn valid_hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// `stats 12.3s live=1 up=0 tunnels=3 tx=1024B rx=2048B ...` -> JSON 对象。
// 数值带 `B` 后缀（字节），`t` 是 CLI 的秒级运行时长。
fn parse_stats(line: &str) -> Option<Value> {
    let rest = line.strip_prefix("stats")?.trim();
    let mut it = rest.split_whitespace();
    let t = it.next()?.trim_end_matches('s').parse::<f64>().ok()?;
    let mut obj = Map::new();
    obj.insert("t".to_string(), json!(t));
    for tok in it {
        let (k, v) = tok.split_once('=')?;
        let v = v.trim_end_matches('B');
        obj.insert(k.to_string(), json!(v.parse::<u64>().ok()?));
    }
    Some(Value::Object(obj))
}

fn kill_child(child: &mut Child) {
    #[cfg(unix)]
    {
        use std::time::Instant;
        let pid = child.id() as i32;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_millis(1500);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[tauri::command]
fn start_proxy(
    app: AppHandle,
    state: State<'_, ProxyProc>,
    cfg: ProxyConfig,
) -> Result<(), String> {
    if !valid_hex32(&cfg.key_hex) {
        return Err("预共享密钥必须是 32 个十六进制字符".into());
    }
    if cfg.host.trim().is_empty() {
        return Err("服务器地址不能为空".into());
    }
    if cfg.port == 0 || cfg.listen_port == 0 {
        return Err("端口不能为 0".into());
    }
    if !(-1..=7).contains(&cfg.k) {
        return Err("k 必须在 -1..7".into());
    }
    if !(576..=9000).contains(&cfg.mtu) {
        return Err("MTU 必须在 576..9000".into());
    }
    if !(0.0..=1.0).contains(&cfg.fec_budget) {
        return Err("FEC 预算必须在 0..1".into());
    }

    let bin = resolve_sidecar(&app)?;
    let mut cmd = Command::new(&bin);
    cmd.arg(format!("--host={}", cfg.host.trim()))
        .arg(format!("--port={}", cfg.port))
        .arg(format!("--listen={}", cfg.listen.trim()))
        .arg(format!("--local-port={}", cfg.listen_port))
        .arg(format!("--mtu={}", cfg.mtu))
        .arg(format!("--fec-budget={}", cfg.fec_budget))
        .arg("--key-env=FCP_PSK")
        .arg("--log=stats:500")
        .env("FCP_PSK", cfg.key_hex.to_ascii_uppercase())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cfg.k >= 0 {
        cmd.arg(format!("--k={}", cfg.k));
    }
    if !cfg.trace.trim().is_empty() {
        cmd.arg(format!("--trace={}", cfg.trace.trim()));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    // The check, the spawn and the registration happen under one lock: two
    // interleaved calls used to both pass the "not running" check, and the
    // second Child overwrote the first without killing it (orphan sidecar,
    // port still bound). Any failure between spawn and registration must kill
    // the child for the same reason (A-06).
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;
    if let Some(child) = guard.as_mut() {
        match child.try_wait() {
            Ok(None) => return Err("代理已在运行".into()),
            Ok(Some(_)) | Err(_) => *guard = None,
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("启动 {} 失败：{e}", bin.display()))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("sidecar 没有 stdout".into());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("sidecar 没有 stderr".into());
        }
    };

    let run_id = state.run_id.fetch_add(1, Ordering::SeqCst) + 1;
    let pid = child.id();
    let child_arc = state.child.clone();
    let run_arc = state.run_id.clone();
    *guard = Some(child);
    drop(guard);
    let _ = app.emit("proxy-state", json!({ "state": "running", "pid": pid }));

    // stdout：stats 行进事件，其余进行日志。
    {
        let app = app.clone();
        let run_arc = run_arc.clone();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if run_arc.load(Ordering::SeqCst) != run_id {
                    break;
                }
                if let Some(stats) = parse_stats(&line) {
                    let _ = app.emit("proxy-stats", stats);
                } else {
                    let _ = app.emit("proxy-log", json!({ "stream": "out", "line": line }));
                }
            }
        });
    }
    // stderr：全部按日志行上报（verbose/告警/错误都在这里）。
    {
        let app = app.clone();
        let run_arc = run_arc.clone();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if run_arc.load(Ordering::SeqCst) != run_id {
                    break;
                }
                let _ = app.emit("proxy-log", json!({ "stream": "err", "line": line }));
            }
        });
    }
    // 进程退出观察者：把自己从槽位摘掉，再把退出码发给界面。
    {
        let app = app.clone();
        let child_arc = child_arc.clone();
        let run_arc = run_arc.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(200));
            let mut guard = match child_arc.lock() {
                Ok(g) => g,
                Err(_) => break,
            };
            let Some(child) = guard.as_mut() else { break };
            match child.try_wait() {
                Ok(Some(status)) => {
                    *guard = None;
                    drop(guard);
                    if run_arc.load(Ordering::SeqCst) == run_id {
                        let _ = app.emit(
                            "proxy-state",
                            json!({ "state": "idle", "code": status.code() }),
                        );
                    }
                    break;
                }
                Ok(None) => {}
                Err(_) => {
                    // try_wait() failing does not mean the child is gone;
                    // clearing the slot without killing it leaked a sidecar
                    // that still owned the listening port (A-06).
                    let mut dead = guard.take();
                    drop(guard);
                    if let Some(mut child) = dead.take() {
                        kill_child(&mut child);
                    }
                    break;
                }
            }
        });
    }
    Ok(())
}

#[tauri::command]
fn stop_proxy(state: State<'_, ProxyProc>) -> Result<(), String> {
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;
    if let Some(mut child) = guard.take() {
        // 让观察者线程不再发 idle（这次停止由命令返回值负责），再收进程。
        state.run_id.fetch_add(1, Ordering::SeqCst);
        kill_child(&mut child);
    }
    Ok(())
}

#[tauri::command]
fn proxy_status(state: State<'_, ProxyProc>) -> String {
    let mut guard = match state.child.lock() {
        Ok(g) => g,
        Err(_) => return "idle".into(),
    };
    if let Some(child) = guard.as_mut() {
        match child.try_wait() {
            Ok(None) => return "running".into(),
            _ => *guard = None,
        }
    }
    "idle".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // 与 apps/cli/reactor.cc::print_stats() 的真实输出逐字段对齐：
    // 这一行是界面所有数字的唯一来源，格式漂移必须在这里红。
    #[test]
    fn parses_real_stats_line() {
        let line = "stats    3.5s live=2 up=1 tunnels=7 tx=1024B rx=2048B bad_entry=0 \
refused=1 hs_failed=2 reset=0 idle=3 clash=0 over=0 bad_cfg=0 no_entropy=0 budget=4 \
unknown=5 tomb=6 duprec=7";
        let v = parse_stats(line).expect("stats line must parse");
        assert!((v["t"].as_f64().unwrap() - 3.5).abs() < 1e-9);
        assert_eq!(v["live"], 2);
        assert_eq!(v["up"], 1);
        assert_eq!(v["tunnels"], 7);
        assert_eq!(v["tx"], 1024);
        assert_eq!(v["rx"], 2048);
        assert_eq!(v["refused"], 1);
        assert_eq!(v["hs_failed"], 2);
        assert_eq!(v["idle"], 3);
        assert_eq!(v["budget"], 4);
        assert_eq!(v["unknown"], 5);
        assert_eq!(v["tomb"], 6);
        assert_eq!(v["duprec"], 7);
    }

    #[test]
    fn non_stats_lines_are_not_stats() {
        assert!(parse_stats("client: socks5/http on 127.0.0.1:1080 -> fcp 1.2.3.4:4460").is_none());
        assert!(parse_stats("stats").is_none());
        // 计数行里出现非数字（例如 future/新增字段想放字符串）时按日志处理，
        // 不半解析出一份错的数字。
        assert!(parse_stats("stats 1.0s live=x").is_none());
    }

    #[test]
    fn key_and_port_validation() {
        assert!(valid_hex32("0123456789abcdef0123456789abcdef"));
        assert!(valid_hex32("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!valid_hex32("0123"));
        assert!(!valid_hex32("zz23456789abcdef0123456789abcdef"));
    }
}

fn main() {
    let child = Arc::new(Mutex::new(None::<Child>));
    let run_id = Arc::new(AtomicU64::new(0));
    let proc_state = ProxyProc {
        child: child.clone(),
        run_id,
    };

    let app = tauri::Builder::default()
        .manage(proc_state)
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            proxy_status
        ])
        .build(tauri::generate_context!())
        .expect("failed to build tauri application");

    app.run(move |_handle, event| {
        if let tauri::RunEvent::ExitRequested { .. } = event {
            if let Ok(mut guard) = child.lock() {
                if let Some(mut c) = guard.take() {
                    kill_child(&mut c);
                }
            }
        }
    });
}
