fn main() {
    const WINDOWS_ICON: &str = "packaging/windows/codex.ico";

    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rerun-if-changed={WINDOWS_ICON}");
        winresource::WindowsResource::new()
            .set_icon(WINDOWS_ICON)
            .set("ProductName", "Codex Fast")
            .set("FileDescription", "Codex Fast")
            .compile()
            .expect("failed to embed the Windows application icon");
    }
}
