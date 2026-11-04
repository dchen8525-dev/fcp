//! FCP 单文件引导器。
//!
//! 发行物布局：
//!
//! ```text
//! [本 exe][zip 载荷][64 字节尾部]
//! ```
//!
//! 尾部（小端）：
//!
//! ```text
//! 0..8    "FCPBOOT1"
//! 8..12   u32 格式版本（当前为 1）
//! 12..16  u32 保留（0）
//! 16..24  u64 载荷偏移
//! 24..32  u64 载荷长度
//! 32..64  SHA-256（载荷内容，用于缓存目录名）
//! ```
//!
//! 首次运行把载荷解压到 `%LOCALAPPDATA%\FCP\bin\<SHA-256 前 8 字节>\`，
//! 之后直接启动缓存里的 `FCP.exe`；不同版本按内容哈希分目录共存，
//! 7 天未使用的旧版本目录会被清理。用户配置由 Qt 的 QSettings 存在注册表
//! （`HKCU\Software\FCP\FCP Client`），与本缓存无关，升级不丢配置。

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::env;
use std::ffi::{c_void, OsString};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FOOTER_LEN: u64 = 64;
const MAGIC: &[u8; 8] = b"FCPBOOT1";
const FORMAT_VERSION: u32 = 1;
const APP_NAME: &str = "FCP.exe";
const SIDECAR_NAME: &str = "fcp-client.exe";
const MARKER: &str = ".ready";
const USED_STAMP: &str = ".used";
const SELFTEST_FLAG: &str = "--fcp-launcher-selftest";
/// 旧版本目录保留期：超过这个时间没有启动过就清理。
const CACHE_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// 半成品解压目录超过这个时间才清理，避免打断正在解压的另一个实例。
const TMP_RETENTION: Duration = Duration::from_secs(60 * 60);

fn main() {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let selftest = args.iter().any(|a| a == SELFTEST_FLAG);
    if let Err(err) = run(&args, selftest) {
        report_error(&err);
        std::process::exit(1);
    }
}

fn run(args: &[OsString], selftest: bool) -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| format!("无法定位自身路径：{e}"))?;
    let footer = read_footer(&exe)?;
    let dir = ensure_payload(&exe, &footer)?;
    touch_used(&dir);
    cleanup_old(&dir);

    if selftest {
        for name in [APP_NAME, SIDECAR_NAME] {
            if !dir.join(name).is_file() {
                return Err(format!("自检失败：缓存里缺少 {name}"));
            }
        }
        let report = format!("ok\ncache={}\n", dir.display());
        let _ = fs::write(selftest_file(), &report);
        // 发布物是 GUI 子系统，标准输出可能不可用；失败就算了。
        let _ = io::stdout().write_all(report.as_bytes());
        return Ok(());
    }

    launch(&dir, args.iter().cloned())
}

#[derive(Debug)]
struct Footer {
    offset: u64,
    len: u64,
    sha256: [u8; 32],
}

fn read_footer(exe: &Path) -> Result<Footer, String> {
    let mut file = File::open(exe).map_err(|e| format!("无法打开自身：{e}"))?;
    let total = file
        .metadata()
        .map_err(|e| format!("无法读取自身大小：{e}"))?
        .len();
    if total < FOOTER_LEN {
        return Err("不是 FCP 单文件发行物：文件太短".into());
    }
    file.seek(SeekFrom::Start(total - FOOTER_LEN))
        .map_err(|e| format!("无法读取引导尾部：{e}"))?;
    let mut buf = [0u8; FOOTER_LEN as usize];
    file.read_exact(&mut buf)
        .map_err(|e| format!("无法读取引导尾部：{e}"))?;
    parse_footer(&buf, total)
}

fn parse_footer(buf: &[u8], total: u64) -> Result<Footer, String> {
    if buf.len() != FOOTER_LEN as usize {
        return Err("引导尾部长度不对".into());
    }
    if &buf[0..8] != &MAGIC[..] {
        return Err("不是 FCP 单文件发行物：缺少引导尾部标记（文件可能被截断）".into());
    }
    let format = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if format != FORMAT_VERSION {
        return Err(format!("不支持的引导格式版本 {format}，请重新下载发行物"));
    }
    let offset = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let len = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    if offset.checked_add(len) != Some(total - FOOTER_LEN) {
        return Err("引导尾部与载荷长度不一致（文件被截断或拼接错误）".into());
    }
    if len == 0 {
        return Err("引导尾部声明的载荷为空".into());
    }
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&buf[32..64]);
    Ok(Footer {
        offset,
        len,
        sha256,
    })
}

fn cache_root() -> Result<PathBuf, String> {
    let base = env::var_os("LOCALAPPDATA")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "环境变量 LOCALAPPDATA 缺失，无法确定缓存目录".to_string())?;
    Ok(base.join("FCP").join("bin"))
}

fn cache_key(sha256: &[u8; 32]) -> String {
    let mut key = String::with_capacity(16);
    for byte in &sha256[..8] {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

fn ready(dir: &Path) -> bool {
    dir.join(APP_NAME).is_file() && dir.join(SIDECAR_NAME).is_file() && dir.join(MARKER).is_file()
}

fn ensure_payload(exe: &Path, footer: &Footer) -> Result<PathBuf, String> {
    let root = cache_root()?;
    let key = cache_key(&footer.sha256);
    let dir = root.join(&key);
    if ready(&dir) {
        return Ok(dir);
    }

    fs::create_dir_all(&root).map_err(|e| format!("无法创建缓存目录 {}：{e}", root.display()))?;

    // 上一次可能留下了半截目录（没有 .ready），先清掉。
    if dir.exists() {
        fs::remove_dir_all(&dir)
            .map_err(|e| format!("无法清理损坏的缓存目录 {}：{e}", dir.display()))?;
    }

    let tmp = root.join(format!(".tmp-{key}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| format!("无法创建临时目录 {}：{e}", tmp.display()))?;
    // Every exit from here on must drop the tmp tree: the per-call cleanups
    // below cover the named failures, but a panic or an early `?` on a future
    // edit would leave a full payload copy on disk until the next launch
    // (TMP_RETENTION = 1 h), once per crash.
    let _tmp_guard = TmpGuard(tmp.clone());

    if let Err(err) = extract_payload(exe, footer, &tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(err);
    }
    for name in [APP_NAME, SIDECAR_NAME] {
        if !tmp.join(name).is_file() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!("载荷里缺少 {name}"));
        }
    }
    if let Err(e) = File::create(tmp.join(MARKER)).and_then(|mut f| f.write_all(key.as_bytes())) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("无法写入缓存标记：{e}"));
    }

    // 目录改名是原子的：另一个实例已经放好同名目录时，直接用它的。
    match fs::rename(&tmp, &dir) {
        Ok(()) => Ok(dir),
        Err(_) if ready(&dir) => {
            let _ = fs::remove_dir_all(&tmp);
            Ok(dir)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(format!(
                "无法把解压结果放到 {}：{e}（可能被占用）",
                dir.display()
            ))
        }
    }
}

fn extract_payload(exe: &Path, footer: &Footer, dest: &Path) -> Result<(), String> {
    let len = usize::try_from(footer.len).map_err(|_| "载荷长度超出本机地址空间".to_string())?;
    let mut file = File::open(exe).map_err(|e| format!("无法打开自身：{e}"))?;
    file.seek(SeekFrom::Start(footer.offset))
        .map_err(|e| format!("无法定位载荷：{e}"))?;
    let mut payload = vec![0u8; len];
    file.read_exact(&mut payload)
        .map_err(|e| format!("无法读取载荷：{e}"))?;

    let mut archive = zip::ZipArchive::new(io::Cursor::new(payload))
        .map_err(|e| format!("载荷不是有效的 zip：{e}"))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| format!("读取载荷条目 {index} 失败：{e}"))?;
        // enclosed_name 拒绝 `..`、绝对路径等越界条目。
        let rel = entry
            .enclosed_name()
            .ok_or_else(|| format!("载荷条目路径非法：{}", entry.name()))?;
        let out = dest.join(&rel);
        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(|e| format!("无法创建 {}：{e}", out.display()))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("无法创建 {}：{e}", parent.display()))?;
        }
        let mut writer =
            File::create(&out).map_err(|e| format!("无法写入 {}：{e}", out.display()))?;
        io::copy(&mut entry, &mut writer)
            .map_err(|e| format!("解压 {} 失败：{e}", out.display()))?;
    }
    Ok(())
}

fn touch_used(dir: &Path) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = fs::write(dir.join(USED_STAMP), secs.to_string());
}

fn cleanup_old(current: &Path) {
    let Ok(root) = cache_root() else {
        return;
    };
    let Ok(entries) = fs::read_dir(&root) else {
        return;
    };
    let now = SystemTime::now();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = current.file_name() {
            if entry.file_name().as_os_str() == name {
                continue;
            }
        }

        let is_tmp = entry.file_name().to_string_lossy().starts_with(".tmp-");
        let last = if is_tmp {
            entry.metadata().ok().and_then(|m| m.modified().ok())
        } else {
            last_used(&path).or_else(|| entry.metadata().ok().and_then(|m| m.modified().ok()))
        };
        let Some(last) = last else {
            continue;
        };
        let retention = if is_tmp {
            TMP_RETENTION
        } else {
            CACHE_RETENTION
        };
        if now.duration_since(last).unwrap_or_default() > retention {
            // 正在运行的旧版本会锁住 exe，删除失败就留到下次。但 Windows 只锁
            // 正在执行的映像本身：旧版本拉起的 sidecar 与资源照样会被删掉，
            // 于是"跑着的旧版"一旦需要子进程或按需加载就废了。先独占打开
            // 主 exe 试探——能打开说明没人持有它，删才安全。
            if in_use(&path) {
                continue;
            }
            let _ = fs::remove_dir_all(&path);
        }
    }
}

/// 解压目录的兜底清理：正常路径由各分支自己删，异常路径（panic、提前 `?`）
/// 靠 Drop 收尾。rename 成功后路径已不存在，remove 失败无关紧要。
struct TmpGuard(PathBuf);

impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 该目录里的主程序是否正被某个进程持有（或根本无法写入）。
///
/// Windows：exe 被运行时以共享读打开，独占写打开会失败（ERROR_SHARING_VIOLATION）。
/// 文件不存在时返回 false——空壳目录照样可以删。
fn in_use(dir: &Path) -> bool {
    let exe = dir.join(APP_NAME);
    if !exe.exists() {
        return false;
    }
    fs::OpenOptions::new().write(true).open(&exe).is_err()
}

fn last_used(dir: &Path) -> Option<SystemTime> {
    let raw = fs::read_to_string(dir.join(USED_STAMP)).ok()?;
    let secs = raw.trim().parse::<u64>().ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

fn launch(dir: &Path, args: impl Iterator<Item = OsString>) -> Result<(), String> {
    let app = dir.join(APP_NAME);
    let mut cmd = Command::new(&app);
    cmd.args(args);
    cmd.current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // GUI 程序本身不建控制台；这个标志只是避免某些环境下闪一下。
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("无法启动 {}：{e}", app.display()))
}

fn selftest_file() -> PathBuf {
    cache_root()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(env::temp_dir)
        .join("selftest.txt")
}

fn report_error(message: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(cache) = cache_root() {
        let root = cache
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(env::temp_dir);
        let _ = fs::create_dir_all(&root);
        if let Ok(mut log) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("launcher.log"))
        {
            let _ = writeln!(log, "[{secs}] {message}");
        }
    }
    #[cfg(windows)]
    message_box("FCP 启动失败", message);
}

#[cfg(windows)]
fn message_box(title: &str, text: &str) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, utype: u32)
            -> i32;
    }
    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONERROR: u32 = 0x0000_0010;
    let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let text: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: 两个字符串都以 NUL 结尾，且在调用期间保持有效。
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn footer_bytes(offset: u64, len: u64, sha: [u8; 32]) -> [u8; FOOTER_LEN as usize] {
        let mut buf = [0u8; FOOTER_LEN as usize];
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        buf[16..24].copy_from_slice(&offset.to_le_bytes());
        buf[24..32].copy_from_slice(&len.to_le_bytes());
        buf[32..64].copy_from_slice(&sha);
        buf
    }

    #[test]
    fn parses_valid_footer() {
        let sha = [7u8; 32];
        let total = 1000 + 64;
        let parsed = parse_footer(&footer_bytes(1000, 0, sha), total).unwrap_err();
        // 载荷长度 0 被拒绝。
        assert!(parsed.contains("为空"));

        let parsed = parse_footer(&footer_bytes(400, 600, sha), total).unwrap();
        assert_eq!(parsed.offset, 400);
        assert_eq!(parsed.len, 600);
        assert_eq!(parsed.sha256, sha);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = footer_bytes(400, 600, [0u8; 32]);
        buf[0] = b'X';
        assert!(parse_footer(&buf, 1064).is_err());
    }

    #[test]
    fn rejects_length_mismatch() {
        let buf = footer_bytes(400, 600, [0u8; 32]);
        assert!(parse_footer(&buf, 1065).is_err());
    }

    #[test]
    fn cache_key_is_16_hex_chars() {
        let mut sha = [0u8; 32];
        sha[0] = 0xde;
        sha[1] = 0xad;
        assert_eq!(cache_key(&sha), "dead000000000000");
    }
}
