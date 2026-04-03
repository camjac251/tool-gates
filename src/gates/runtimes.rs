//! Language runtime permission gate (python, node, ruby, deno, etc.).
//!
//! Uses declarative rules from generated code. No custom handlers needed.

use crate::generated::rules::check_runtimes_gate;
use crate::models::{CommandInfo, GateResult};

/// Check language runtime commands.
pub fn check_runtimes(cmd: &CommandInfo) -> GateResult {
    check_runtimes_gate(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === python3 ===

    #[test]
    fn test_python_version_allows() {
        let result = check_runtimes(&cmd("python3", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_python_v_flag_allows() {
        let result = check_runtimes(&cmd("python3", &["-V"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_python_c_asks() {
        let result = check_runtimes(&cmd("python3", &["-c", "print('hello')"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_python_m_asks() {
        let result = check_runtimes(&cmd("python3", &["-m", "http.server"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_python_script_asks() {
        let result = check_runtimes(&cmd("python3", &["script.py"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_python_alias_works() {
        let result = check_runtimes(&cmd("python", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === node ===

    #[test]
    fn test_node_version_allows() {
        let result = check_runtimes(&cmd("node", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_node_check_allows() {
        let result = check_runtimes(&cmd("node", &["-c", "file.js"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_node_syntax_check_allows() {
        let result = check_runtimes(&cmd("node", &["--check", "file.js"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_node_eval_asks() {
        let result = check_runtimes(&cmd("node", &["-e", "console.log('hello')"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_node_script_asks() {
        let result = check_runtimes(&cmd("node", &["server.js"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === ruby ===

    #[test]
    fn test_ruby_version_allows() {
        let result = check_runtimes(&cmd("ruby", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ruby_syntax_check_allows() {
        let result = check_runtimes(&cmd("ruby", &["-c", "script.rb"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ruby_e_asks() {
        let result = check_runtimes(&cmd("ruby", &["-e", "puts 'hello'"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === deno ===

    #[test]
    fn test_deno_check_allows() {
        let result = check_runtimes(&cmd("deno", &["check", "mod.ts"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_deno_lint_allows() {
        let result = check_runtimes(&cmd("deno", &["lint"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_deno_test_allows() {
        let result = check_runtimes(&cmd("deno", &["test"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_deno_run_asks() {
        let result = check_runtimes(&cmd("deno", &["run", "server.ts"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_deno_fmt_check_allows() {
        let result = check_runtimes(&cmd("deno", &["fmt", "--check"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_deno_fmt_asks() {
        let result = check_runtimes(&cmd("deno", &["fmt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_deno_install_asks() {
        let result = check_runtimes(&cmd("deno", &["install"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === php ===

    #[test]
    fn test_php_version_allows() {
        let result = check_runtimes(&cmd("php", &["-v"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_php_lint_allows() {
        let result = check_runtimes(&cmd("php", &["-l", "file.php"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_php_modules_allows() {
        let result = check_runtimes(&cmd("php", &["-m"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_php_r_asks() {
        let result = check_runtimes(&cmd("php", &["-r", "echo 'hello';"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === dotnet ===

    #[test]
    fn test_dotnet_version_allows() {
        let result = check_runtimes(&cmd("dotnet", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_dotnet_build_allows() {
        let result = check_runtimes(&cmd("dotnet", &["build"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_dotnet_test_allows() {
        let result = check_runtimes(&cmd("dotnet", &["test"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_dotnet_publish_asks() {
        let result = check_runtimes(&cmd("dotnet", &["publish"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === java ===

    #[test]
    fn test_java_version_allows() {
        let result = check_runtimes(&cmd("java", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_java_run_asks() {
        let result = check_runtimes(&cmd("java", &["MyApp"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === swift ===

    #[test]
    fn test_swift_build_allows() {
        let result = check_runtimes(&cmd("swift", &["build"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_swift_test_allows() {
        let result = check_runtimes(&cmd("swift", &["test"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_swift_run_asks() {
        let result = check_runtimes(&cmd("swift", &["run"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === python aliases ===

    #[test]
    fn test_python312_alias_allows() {
        let result = check_runtimes(&cmd("python3.12", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_python312_script_asks() {
        let result = check_runtimes(&cmd("python3.12", &["script.py"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === lua/luajit ===

    #[test]
    fn test_lua_version_allows() {
        let result = check_runtimes(&cmd("lua", &["-v"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_luajit_version_allows() {
        let result = check_runtimes(&cmd("luajit", &["-v"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_luajit_script_asks() {
        let result = check_runtimes(&cmd("luajit", &["script.lua"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_lua_eval_asks() {
        let result = check_runtimes(&cmd("lua", &["-e", "print('hello')"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === deno additional ===

    #[test]
    fn test_deno_bench_allows() {
        let result = check_runtimes(&cmd("deno", &["bench"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_deno_add_asks() {
        let result = check_runtimes(&cmd("deno", &["add", "oak"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_deno_publish_asks() {
        let result = check_runtimes(&cmd("deno", &["publish"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === dotnet additional ===

    #[test]
    fn test_dotnet_format_check_allows() {
        let result = check_runtimes(&cmd("dotnet", &["format", "--check"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_dotnet_format_verify_no_changes_allows() {
        let result = check_runtimes(&cmd("dotnet", &["format", "--verify-no-changes"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_dotnet_format_asks() {
        let result = check_runtimes(&cmd("dotnet", &["format"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_dotnet_add_asks() {
        let result = check_runtimes(&cmd("dotnet", &["add", "package", "Newtonsoft.Json"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_dotnet_run_allows() {
        let result = check_runtimes(&cmd("dotnet", &["run"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === elixir ===

    #[test]
    fn test_elixir_version_allows() {
        let result = check_runtimes(&cmd("elixir", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_elixir_script_asks() {
        let result = check_runtimes(&cmd("elixir", &["script.exs"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_elixir_eval_asks() {
        let result = check_runtimes(&cmd("elixir", &["-e", "IO.puts('hello')"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === iex ===

    #[test]
    fn test_iex_version_allows() {
        let result = check_runtimes(&cmd("iex", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_iex_bare_asks() {
        let result = check_runtimes(&cmd("iex", &[]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-runtime ===

    #[test]
    fn test_non_runtime_skips() {
        let result = check_runtimes(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
