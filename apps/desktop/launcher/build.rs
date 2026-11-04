fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../src-tauri/icons/icon.ico");
    println!("cargo:rerun-if-env-changed=FCP_VERSION");

    // 只在 Windows 上编译资源；Linux 侧不产出这个引导器。
    #[cfg(windows)]
    {
        let version =
            std::env::var("FCP_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());
        let mut res = tauri_winres::WindowsResource::new();
        res.set_icon("../src-tauri/icons/icon.ico");
        res.set("ProductName", "FCP");
        res.set("FileDescription", "FCP 客户端启动器");
        res.set("ProductVersion", &version);
        res.set("FileVersion", &version);
        res.compile().expect("编译 Windows 资源失败");
    }
}
