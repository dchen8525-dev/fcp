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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

// One speed test at a time. It runs as a second fcp-client process: the bench
// speaks FCP itself, so it must live where the protocol lives, and a separate
// process keeps it from touching the proxy's session.
struct SpeedTestState {
    running: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SpeedTestConfig {
    host: String,
    port: u16,
    key_hex: String,
    seconds: u64,
    mtu: u16,
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

/// 子进程随 GUI 一起死。
///
/// `RunEvent::ExitRequested` 只覆盖"正常退出"这一条路：任务管理器结束进程、
/// GUI panic 后 abort、其它路径上的 `std::process::exit`、注销 —— 这些情况下
/// `fcp-client` 会留下来继续占着本地监听端口和隧道，下次启动直接
/// "Address already in use"。两套机制补上其余路径：
///
/// * Windows：一个 `KILL_ON_JOB_CLOSE` 的 Job Object，GUI 进程结束时内核关闭
///   最后一个句柄，Job 内的所有进程被一起终止。句柄故意泄漏到进程结束，
///   因为"关闭它"正是触发条件。
/// * Unix：`PR_SET_PDEATHSIG`，父进程消失时内核给子进程发 SIGKILL。它是按
///   **父线程**计算的，所以命令处理器必须是长寿线程 —— 这正是 Tauri sync
///   command 的运行方式（阻塞命令要写成 async 才不会卡界面）。`getppid()==1`
///   兜住"设置之前父进程就已经死了"的竞态。
#[cfg(windows)]
mod reaper {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::sync::OnceLock;

    type Handle = isize;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimitInformation {
        basic: BasicLimitInformation,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *mut std::ffi::c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            class: i32,
            info: *mut std::ffi::c_void,
            len: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    }

    /// 进程内唯一的 Job。创建失败返回 0，后续 assign 静默跳过（只丢失
    /// 强杀兜底，不阻断启动）。
    fn job() -> Handle {
        static JOB: OnceLock<Handle> = OnceLock::new();
        *JOB.get_or_init(|| unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            if job == 0 {
                return 0;
            }
            let mut info = ExtendedLimitInformation::default();
            info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ExtendedLimitInformation>() as u32,
            );
            if ok == 0 {
                return 0;
            }
            job
        })
    }

    pub fn assign(child: &Child) {
        let job = job();
        if job == 0 {
            return;
        }
        // 已被 Tauri/父 Job 收编时会失败（嵌套 Job 需要 Windows 8+）；失败只
        // 意味着退回 ExitRequested 那一层保护。
        unsafe {
            AssignProcessToJobObject(job, child.as_raw_handle() as Handle);
        }
    }
}

#[cfg(windows)]
fn arm_parent_death(_cmd: &mut std::process::Command) {}

#[cfg(unix)]
fn arm_parent_death(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // 父进程在我们设好之前就没了：此时 PDEATHSIG 不会再触发，必须
            // 自己走，否则会被 init 收养活成孤儿。
            if libc::getppid() == 1 {
                libc::_exit(127);
            }
            Ok(())
        });
    }
}

#[cfg(windows)]
fn assign_to_reaper(child: &Child) {
    reaper::assign(child);
}

#[cfg(unix)]
fn assign_to_reaper(_child: &Child) {}

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
        // Raise the autotune ceiling (and therefore the advertised receive
        // capacity) to 4 MiB, but leave the start at the engine default: BBR
        // (v2 by default) finds the path's own operating point from there.
        // The empty START in --window=:4096 is what keeps the start implicit,
        // so the prewarm cache can still seed it from the previous session.
        .arg("--window=:4096")
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
    arm_parent_death(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("启动 {} 失败：{e}", bin.display()))?;
    assign_to_reaper(&child);
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

// Spawns a second fcp-client in bench mode and turns its `@speedtest` lines
// into events. The child speaks FCP on the server's normal UDP port (the
// server needs `--speedtest`), so the running proxy is not involved at all and
// can keep serving traffic while the test runs.
#[tauri::command]
fn start_speedtest(
    app: AppHandle,
    speed: State<'_, SpeedTestState>,
    cfg: SpeedTestConfig,
) -> Result<(), String> {
    if cfg.host.trim().is_empty() {
        return Err("服务器地址不能为空".into());
    }
    if cfg.port == 0 {
        return Err("端口不能为 0".into());
    }
    if !valid_hex32(&cfg.key_hex) {
        return Err("预共享密钥必须是 32 个十六进制字符".into());
    }
    if !(3..=30).contains(&cfg.seconds) {
        return Err("测速时长必须在 3..30 秒".into());
    }
    if !(576..=9000).contains(&cfg.mtu) {
        return Err("MTU 必须在 576..9000".into());
    }
    let bin = resolve_sidecar(&app)?;
    if speed
        .running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("测速正在进行".into());
    }

    let mut cmd = Command::new(&bin);
    cmd.arg(format!("--host={}", cfg.host.trim()))
        .arg(format!("--port={}", cfg.port))
        .arg(format!("--mtu={}", cfg.mtu))
        .arg(format!("--speedtest-seconds={}", cfg.seconds))
        .arg("--speedtest")
        .arg("--key-env=FCP_PSK")
        .env("FCP_PSK", cfg.key_hex.to_ascii_uppercase())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    arm_parent_death(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            speed.running.store(false, Ordering::SeqCst);
            return Err(format!("启动 {} 失败：{e}", bin.display()));
        }
    };
    assign_to_reaper(&child);
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            speed.running.store(false, Ordering::SeqCst);
            return Err("测速进程没有 stdout".into());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            speed.running.store(false, Ordering::SeqCst);
            return Err("测速进程没有 stderr".into());
        }
    };
    {
        // A poisoned lock must not drop `child` on the floor: Child's Drop does
        // not kill anything, so the speed test would keep the UDP socket busy
        // for its whole duration while `running` stayed true forever (every
        // later start would be refused as "already running").
        let mut guard = match speed.child.lock() {
            Ok(guard) => guard,
            Err(_) => {
                let mut child = child;
                kill_child(&mut child);
                speed.running.store(false, Ordering::SeqCst);
                return Err("测速状态不可用（锁已中毒）".into());
            }
        };
        if let Some(mut stale) = guard.take() {
            kill_child(&mut stale);
        }
        *guard = Some(child);
    }

    let running = speed.running.clone();
    let child_arc = speed.child.clone();
    let app_out = app.clone();
    thread::spawn(move || {
        // The child prints one JSON object per line and exits; a run that never
        // reached the server still has to produce a done event so the UI does
        // not stay in "测速中".
        let mut done = false;
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let Some(rest) = line.strip_prefix("@speedtest ") else {
                let _ = app_out.emit("proxy-log", json!({ "stream": "out", "line": line }));
                continue;
            };
            let Ok(value) = serde_json::from_str::<Value>(rest) else {
                continue;
            };
            match value.get("event").and_then(Value::as_str) {
                Some("progress") => {
                    let _ = app_out.emit(
                        "speedtest-progress",
                        json!({
                            "direction": value.get("direction").cloned().unwrap_or(Value::Null),
                            "bytes": value.get("bytes").cloned().unwrap_or(Value::Null),
                            "elapsedMs": value.get("elapsedMs").cloned().unwrap_or(Value::Null),
                        }),
                    );
                }
                Some("done") => {
                    done = true;
                    let _ = app_out.emit(
                        "speedtest-done",
                        json!({
                            "seconds": value.get("seconds").cloned().unwrap_or(Value::Null),
                            "download": value.get("download").cloned().unwrap_or(Value::Null),
                            "upload": value.get("upload").cloned().unwrap_or(Value::Null),
                            "error": value.get("error").cloned().unwrap_or(Value::Null),
                        }),
                    );
                }
                _ => {}
            }
        }
        if !done {
            let _ = app_out.emit(
                "speedtest-done",
                json!({
                    "download": Value::Null,
                    "upload": Value::Null,
                    "error": "测速进程异常退出（确认服务端以 --speedtest 启动）",
                }),
            );
        }
        running.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = child_arc.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.wait();
            }
        }
    });

    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = app.emit("proxy-log", json!({ "stream": "err", "line": line }));
        }
    });
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
            _ => {
                // Reap the exit status. Dropping the Child without wait()
                // leaves a zombie on Unix for as long as the GUI lives.
                if let Some(mut done) = guard.take() {
                    let _ = done.wait();
                }
            }
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
unknown=5 tomb=6 duprec=7 loss_in_ppm=1200 loss_in_n=5000 loss_out_ppm=300 loss_out_n=7000";
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
        assert_eq!(v["loss_in_ppm"], 1200);
        assert_eq!(v["loss_in_n"], 5000);
        assert_eq!(v["loss_out_ppm"], 300);
        assert_eq!(v["loss_out_n"], 7000);
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

fn resolve_sidecar_bare() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("FCP_PROXY_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("FCP_PROXY_BIN={} 不是文件", p.display()));
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

// 无界面的测速自检：`FCP.exe --fcp-speedtest-selftest`（环境变量指定参数）。
// 与界面走同一条路径（第二个 fcp-client 进程），服务端需以 --speedtest 启动；
// 结果同时写到 %TEMP%\fcp-speedtest.txt（release 是 GUI 子系统，没有控制台）。
fn speedtest_selftest() -> i32 {
    let get = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.into());
    let write_temp = |text: &str| {
        if let Ok(dir) = std::env::var("TEMP").or_else(|_| std::env::var("TMPDIR")) {
            let _ = std::fs::write(PathBuf::from(dir).join("fcp-speedtest.txt"), text);
        }
    };
    let bin = match resolve_sidecar_bare() {
        Ok(bin) => bin,
        Err(err) => {
            println!("{err}");
            write_temp(&err);
            return 1;
        }
    };
    let key = std::env::var("FCP_SPEEDTEST_KEY")
        .or_else(|_| std::env::var("FCP_PSK"))
        .unwrap_or_default();
    let seconds = get("FCP_SPEEDTEST_SECONDS", "8")
        .parse::<u64>()
        .unwrap_or(8)
        .clamp(3, 30);
    let mut cmd = Command::new(&bin);
    cmd.arg(format!("--host={}", get("FCP_SPEEDTEST_HOST", "127.0.0.1")))
        .arg(format!("--port={}", get("FCP_SPEEDTEST_PORT", "4460")))
        .arg(format!("--speedtest-seconds={seconds}"))
        .arg("--speedtest")
        .arg("--key-env=FCP_PSK")
        .env("FCP_PSK", key)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => {
            let text = format!("启动 {} 失败：{err}", bin.display());
            println!("{text}");
            write_temp(&text);
            return 1;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut text = String::new();
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("@speedtest ") else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(rest) else {
            continue;
        };
        if value.get("event").and_then(Value::as_str) == Some("done") {
            text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| rest.to_string());
        }
    }
    if text.is_empty() {
        text = format!(
            "{{\"error\":\"测速没有完成\",\"stderr\":{}}}",
            json!(stderr.trim())
        );
    }
    println!("{text}");
    if !stderr.trim().is_empty() {
        eprintln!("{stderr}");
    }
    write_temp(&text);
    i32::from(!text.contains("\"mbps\""))
}

fn main() {
    if std::env::args().any(|a| a == "--fcp-speedtest-selftest") {
        std::process::exit(speedtest_selftest());
    }
    let child = Arc::new(Mutex::new(None::<Child>));
    let run_id = Arc::new(AtomicU64::new(0));
    let proc_state = ProxyProc {
        child: child.clone(),
        run_id,
    };
    let speed_child = Arc::new(Mutex::new(None::<Child>));
    let speed_state = SpeedTestState {
        running: Arc::new(AtomicBool::new(false)),
        child: speed_child.clone(),
    };

    let app = tauri::Builder::default()
        .manage(proc_state)
        .manage(speed_state)
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            proxy_status,
            start_speedtest
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
            if let Ok(mut guard) = speed_child.lock() {
                if let Some(mut c) = guard.take() {
                    kill_child(&mut c);
                }
            }
        }
    });
}
