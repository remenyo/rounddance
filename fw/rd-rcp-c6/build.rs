fn main() {
    // Same sdkconfig guard as the standalone images: fail fast if
    // the esp-idf-sys-consumed defaults cannot carry the main-task
    // stack size (silent-drop boot-loops otherwise).
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let defaults = manifest.join("sdkconfig.defaults");
    let body = std::fs::read_to_string(&defaults)
        .unwrap_or_else(|e| panic!("missing {}: {e}", defaults.display()));
    assert!(
        body.lines()
            .any(|l| l.trim() == "CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384"),
        "sdkconfig.defaults lacks CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384"
    );
    assert!(
        body.lines()
            .any(|l| l.trim() == "CONFIG_IDF_TARGET=\"esp32c6\""),
        "sdkconfig.defaults lacks CONFIG_IDF_TARGET esp32c6"
    );
    for pin in [
        "CONFIG_COMPILER_CXX_EXCEPTIONS=n",
        "CONFIG_COMPILER_CXX_RTTI=n",
    ] {
        assert!(
            body.lines().any(|l| l.trim() == pin),
            "sdkconfig.defaults lacks {pin} (C++ without RTTI/exceptions)"
        );
    }
    if let Ok(ws) = std::env::var("CARGO_WORKSPACE_DIR") {
        assert!(
            std::path::Path::new(&ws).join("sdkconfig.defaults").is_file(),
            "CARGO_WORKSPACE_DIR={ws} has no sdkconfig.defaults"
        );
    }
    // Build-time pin overrides are read via `option_env!`: track
    // them so a changed pin rebuilds instead of reusing a stale image.
    println!("cargo:rerun-if-env-changed=RD_RCP_RX_PIN");
    println!("cargo:rerun-if-env-changed=RD_RCP_TX_PIN");
    embuild::espidf::sysenv::output();
}
