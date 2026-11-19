use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wiz-extract"))
}
#[test]
fn decode_reports_operands_and_rejects_truncated_input() {
    let p = command()
        .args(["decode", "--hex", "48 8b 45 a0", "--ip", "0x1000"])
        .output()
        .unwrap();
    assert!(p.status.success());
    let v: serde_json::Value = serde_json::from_slice(&p.stdout).unwrap();
    assert_eq!(v[0]["ip"], 4096);
    assert_eq!(v[0]["operands"][1]["Memory"]["displacement"], -96);
    let p = command()
        .args(["decode", "--hex", "48 8b 45"])
        .output()
        .unwrap();
    assert!(!p.status.success());
    assert!(String::from_utf8_lossy(&p.stderr).contains("truncated"));
}
#[test]
fn invalid_options_explain_the_problem() {
    for (args, expected) in [
        (vec!["--exe"], "Missing value for --exe"),
        (vec!["--exe", "--report"], "Missing value for --exe"),
        (
            vec!["--exe", "one", "--python", "--python"],
            "Use --python only once",
        ),
        (vec!["--unexpected", "x"], "Unknown option \"--unexpected\""),
        (vec!["--exe", "one", "--exe", "two"], "Use --exe only once"),
        (
            vec!["compare", "--before", "x"],
            "Missing required option --after",
        ),
        (
            vec![
                "--exe",
                "one",
                "--report",
                "generated/wiz_hooks.py",
                "--python",
            ],
            "Choose a --report path other than generated/wiz_hooks.py",
        ),
    ] {
        let output = command().args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{stderr}");
    }
}
#[test]
fn compare_classifies_layout_changes_and_no_change() {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "deimos-extract-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let before = dir.join("before.json");
    let after = dir.join("after.json");
    let b = serde_json::json!({"schema_version":1,"resolver_version":1,"hooks":{"chat":{"finding":{"target_rva":123,"overwrite_size":7,"locations":{"source":-128},"dependencies":{},"evidence":[]},"error":null}}});
    let mut a = b.clone();
    a["hooks"]["chat"]["finding"]["locations"]["source"] = (-96).into();
    fs::write(&before, b.to_string()).unwrap();
    fs::write(&after, a.to_string()).unwrap();
    let p = command()
        .arg("compare")
        .arg("--before")
        .arg(&before)
        .arg("--after")
        .arg(&after)
        .output()
        .unwrap();
    assert!(p.status.success());
    let v: serde_json::Value = serde_json::from_slice(&p.stdout).unwrap();
    assert_eq!(v["changes"]["chat"]["kind"], "layout_changed");
    let p = command()
        .arg("compare")
        .arg("--before")
        .arg(&before)
        .arg("--after")
        .arg(&before)
        .output()
        .unwrap();
    assert!(p.status.success());
    let v: serde_json::Value = serde_json::from_slice(&p.stdout).unwrap();
    assert!(v["changes"].as_object().unwrap().is_empty());
    fs::remove_dir_all(dir).unwrap();
}
