fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Embed admin-elevation manifest (needed for wintun adapter + routes)
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:level='requireAdministrator',uiAccess='false'");
    }
    tauri_build::build();
}
