//! Real-binary regression tests for `tool-gates doctor`.

use std::process::{Command, Output};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

fn isolated_command(temp: &tempfile::TempDir) -> Command {
    let mut command = Command::new(bin_path());
    command
        .current_dir(temp.path())
        .env("HOME", temp.path().join("home"))
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("XDG_CACHE_HOME", temp.path().join("cache"))
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR");
    command
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr utf8")
}

#[test]
fn doctor_uses_xdg_config_path_and_reports_every_disabled_feature() {
    let temp = tempfile::tempdir().expect("doctor tempdir");
    let config_dir = temp.path().join("config/tool-gates");
    std::fs::create_dir_all(&config_dir).expect("create config directory");
    let config_path = config_dir.join("config.toml");
    std::fs::write(
        &config_path,
        "[features]\ngit_aliases = false\ndesign_lint = false\ncomment_lint = false\n",
    )
    .expect("write config");

    let output = isolated_command(&temp)
        .arg("doctor")
        .output()
        .expect("run doctor");
    let stderr = stderr(&output);

    assert!(
        stderr.contains(&format!("Config: {} (valid)", config_path.display())),
        "doctor did not report the XDG config path: {stderr}"
    );
    assert!(
        stderr.contains("Features disabled: git_aliases, design_lint, comment_lint"),
        "doctor omitted disabled features: {stderr}"
    );
}

#[test]
fn doctor_help_does_not_run_health_checks() {
    for flag in ["--help", "-h"] {
        let temp = tempfile::tempdir().expect("doctor tempdir");
        let output = isolated_command(&temp)
            .args(["doctor", flag])
            .output()
            .expect("run doctor help");
        let stderr = stderr(&output);

        assert!(output.status.success(), "doctor {flag} failed: {stderr}");
        assert!(stderr.contains("USAGE:"), "missing doctor help: {stderr}");
        assert!(
            !stderr.contains("Version:")
                && !stderr.contains("Hooks (")
                && !stderr.contains("checks passed"),
            "doctor {flag} ran health checks: {stderr}"
        );
    }
}
