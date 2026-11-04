fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let defaults = manifest.join("sdkconfig.defaults");
    let body = std::fs::read_to_string(&defaults)
        .unwrap_or_else(|e| panic!("missing {}: {e}", defaults.display()));
    assert!(
        body.lines()
            .any(|l| l.trim() == "CONFIG_ESP_MAIN_TASK_STACK_SIZE=32768"),
        "sdkconfig.defaults lacks CONFIG_ESP_MAIN_TASK_STACK_SIZE=32768"
    );
    assert!(
        body.lines()
            .any(|l| l.trim() == "CONFIG_ESP_IPC_TASK_STACK_SIZE=4096"),
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
    if let Ok(ws) = std::env::var("CARGO_WORKSPACE_DIR") {
        assert!(
            std::path::Path::new(&ws).join("sdkconfig.defaults").is_file(),
            "CARGO_WORKSPACE_DIR={ws} has no sdkconfig.defaults"
        );
    }
    println!("cargo:rerun-if-env-changed=RD_NETKEY_HEX");
    if std::env::var("RD_NETKEY_HEX").is_err() {
        println!(
            "cargo:warning=RD_NETKEY_HEX unset: image runs the lab-default test key (set RD_NETKEY_HEX=<(32 hex)> for deployment)"
        );
    }
    embuild::espidf::sysenv::output();
}
