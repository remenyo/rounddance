fn main() {
    // w87-sdkcfg guard: fail fast if the sdkconfig.defaults esp-idf-sys will
    // consume cannot carry our main-task stack size (w86-reclimb3 boot-looped
    // on the silent 3584-byte default when a custom CARGO_TARGET_DIR broke
    // esp-idf-sys workspace-root guessing).
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let defaults = manifest.join("sdkconfig.defaults");
    let body = std::fs::read_to_string(&defaults)
        .unwrap_or_else(|e| panic!("missing {}: {e}", defaults.display()));
    assert!(
        body.lines().any(|l| l.trim() == "CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384"),
        "sdkconfig.defaults lacks CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384"
    );
    assert!(
        body.lines().any(|l| l.trim() == "CONFIG_ESP_IPC_TASK_STACK_SIZE=4096"),
        "sdkconfig.defaults lacks CONFIG_ESP_IPC_TASK_STACK_SIZE=4096"
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
    // The relative "sdkconfig.defaults" lookup is rooted at CARGO_WORKSPACE_DIR
    // when set, else at embuild's OUT_DIR guess (wrong under custom target dirs).
    if let Ok(ws) = std::env::var("CARGO_WORKSPACE_DIR") {
        assert!(
            std::path::Path::new(&ws).join("sdkconfig.defaults").is_file(),
            "CARGO_WORKSPACE_DIR={ws} has no sdkconfig.defaults; esp-idf-sys would silently drop our defaults"
        );
    }
    embuild::espidf::sysenv::output();
}
