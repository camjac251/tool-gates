//! Network command permission gate (curl, wget, ssh, etc.).
//!
//! Uses declarative rules for simple cases, custom logic for complex flag parsing.

use crate::gates::helpers::{find_http_url, get_flag_value, has_any_flag, is_github_content_url};
use crate::generated::rules::{
    check_curl_declarative, check_nc_declarative, check_nmap_declarative, check_rsync_declarative,
    check_scp_declarative, check_sftp_declarative, check_socat_declarative, check_ssh_declarative,
    check_telnet_declarative, check_wget_declarative,
};
use crate::models::{CommandInfo, GateResult};

/// Ask reason emitted when a GET-ish network command targets GitHub-hosted
/// content. `gh api` is strictly better there: it authenticates, follows the
/// rate-limit budget (5000/hr vs 60/hr anonymous), and works on private repos
/// without hitting 404.
const GH_API_REASON: &str = "Use `gh api repos/OWNER/REPO/contents/PATH` (or `gh release download TAG` for release assets) instead - preserves auth, rate limits, and works on private repos";

/// Check network commands.
pub fn check_network(cmd: &CommandInfo) -> GateResult {
    // Strip path prefix to handle /usr/bin/curl etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    match program {
        "curl" => check_curl(cmd),
        "wget" => check_wget(cmd),
        "ssh" => check_ssh(cmd),
        "scp" => check_scp(cmd),
        "sftp" => check_sftp(cmd),
        "rsync" => check_rsync(cmd),
        "nc" | "ncat" | "netcat" => check_netcat(cmd),
        "http" | "https" | "xh" => check_httpie(cmd),
        "nmap" => {
            check_nmap_declarative(cmd).unwrap_or_else(|| GateResult::ask("nmap: Port scanning"))
        }
        "socat" => {
            check_socat_declarative(cmd).unwrap_or_else(|| GateResult::ask("socat: Network relay"))
        }
        "telnet" => check_telnet_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("telnet: Network connection")),
        _ => GateResult::skip(),
    }
}

/// Check curl command - complex flag parsing for HTTP methods and data.
fn check_curl(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Version/help - try declarative
    if has_any_flag(args, &["--version", "-h", "--help"]) {
        return check_curl_declarative(cmd).unwrap_or_else(GateResult::allow);
    }

    // HEAD requests are always safe
    if has_any_flag(args, &["-I", "--head"]) {
        return GateResult::allow();
    }

    // Get HTTP method (defaults to GET)
    let method = get_flag_value(args, &["-X", "--request"]).unwrap_or("GET");

    // Data flags imply mutation
    let data_flags = [
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--data-ascii",
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
        "--json",
    ];
    let has_data = has_any_flag(args, &data_flags);

    if has_data {
        return GateResult::ask(format!("curl: {} with data", method.to_uppercase()));
    }

    // Non-GET methods
    let method_upper = method.to_uppercase();
    if matches!(method_upper.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
        return GateResult::ask(format!("curl: {method_upper} request"));
    }

    // Downloading to file
    if has_any_flag(args, &["-o", "--output", "-O", "--remote-name"]) {
        return GateResult::ask("curl: Downloading file");
    }

    // GitHub raw/API content - nudge toward `gh api` before falling through
    if let Some(url) = find_http_url(args) {
        if is_github_content_url(url) {
            return GateResult::ask(GH_API_REASON);
        }
    }

    // Simple GET - allow
    GateResult::allow()
}

/// Check wget command.
fn check_wget(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Version/help - try declarative
    if args
        .iter()
        .any(|a| a == "--version" || a == "-h" || a == "--help")
    {
        return check_wget_declarative(cmd).unwrap_or_else(GateResult::allow);
    }

    // Spider mode - read only
    if args.iter().any(|a| a == "--spider") {
        return GateResult::allow();
    }

    // Check for dangerous patterns
    for arg in args {
        match arg.as_str() {
            "-O" | "--output-document" | "-P" | "--directory-prefix" => {
                return GateResult::ask("wget: Downloading file");
            }
            "-r" | "--recursive" => return GateResult::ask("wget: Recursive download"),
            "-m" | "--mirror" => return GateResult::ask("wget: Mirroring site"),
            "--post-data" | "--post-file" => return GateResult::ask("wget: POST request"),
            _ => {}
        }
    }

    // Default wget downloads - ask
    GateResult::ask("wget: Downloading")
}

/// Check ssh command.
fn check_ssh(cmd: &CommandInfo) -> GateResult {
    check_ssh_declarative(cmd).unwrap_or_else(|| GateResult::ask("ssh: Remote connection"))
}

/// Check scp command.
fn check_scp(cmd: &CommandInfo) -> GateResult {
    check_scp_declarative(cmd).unwrap_or_else(|| GateResult::ask("scp: File transfer"))
}

/// Check sftp command.
fn check_sftp(cmd: &CommandInfo) -> GateResult {
    check_sftp_declarative(cmd).unwrap_or_else(|| GateResult::ask("sftp: File transfer"))
}

/// Check rsync command.
fn check_rsync(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Dry-run is safe
    if args.iter().any(|a| a == "-n" || a == "--dry-run") {
        return GateResult::allow();
    }

    // Use declarative for version/help
    if let Some(result) = check_rsync_declarative(cmd) {
        if matches!(result.decision, crate::models::Decision::Allow) {
            return result;
        }
    }

    GateResult::ask("rsync: File sync")
}

/// Check netcat commands.
fn check_netcat(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Execute mode - blocked (reverse shell pattern)
    // -e, -c/--sh-exec, --exec, --lua-exec all execute commands
    if args
        .iter()
        .any(|a| a == "-e" || a == "-c" || a == "--sh-exec" || a == "--exec" || a == "--lua-exec")
    {
        return GateResult::block("Netcat execute mode blocked (reverse shell risk)");
    }

    // Use declarative for blocks
    if let Some(result) = check_nc_declarative(cmd) {
        if matches!(result.decision, crate::models::Decision::Block) {
            return result;
        }
    }

    // Listen mode - ask
    if args.iter().any(|a| a == "-l") {
        return GateResult::ask("netcat: Listen mode (opens port)");
    }

    // Regular connection - ask
    GateResult::ask("netcat: Network connection")
}

/// Check HTTPie-style clients (http, https, xh).
fn check_httpie(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::ask("httpie: No URL specified");
    }

    // Check for non-GET methods
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    if args
        .iter()
        .any(|a| methods.contains(&a.to_uppercase().as_str()))
    {
        return GateResult::ask("httpie: Mutating request");
    }

    // Check for data (key=value or key:=value)
    if args.iter().any(|a| a.contains('=')) {
        return GateResult::ask("httpie: Request with data");
    }

    // Check for download
    if args.iter().any(|a| a == "-d" || a == "--download") {
        return GateResult::ask("httpie: Downloading file");
    }

    // GitHub raw/API content - nudge toward `gh api` before falling through
    if let Some(url) = find_http_url(args) {
        if is_github_content_url(url) {
            return GateResult::ask(GH_API_REASON);
        }
    }

    // Simple GET - allow
    GateResult::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd as make_cmd;
    use crate::models::Decision;

    fn curl(args: &[&str]) -> CommandInfo {
        make_cmd("curl", args)
    }

    fn wget(args: &[&str]) -> CommandInfo {
        make_cmd("wget", args)
    }

    fn rsync(args: &[&str]) -> CommandInfo {
        make_cmd("rsync", args)
    }

    fn nc(args: &[&str]) -> CommandInfo {
        make_cmd("nc", args)
    }

    // === curl ===

    #[test]
    fn test_curl_get_allows() {
        let allow_cmds = [
            &["https://example.com"][..],
            &["-I", "https://example.com"],
            &["--head", "https://example.com"],
            &["--version"],
        ];

        for args in allow_cmds {
            let result = check_network(&curl(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_curl_mutating_asks() {
        let ask_cmds = [
            &["-X", "POST", "https://example.com"][..],
            &["-X", "PUT", "https://example.com"],
            &["-XDELETE", "https://example.com"],
            &["-d", "data", "https://example.com"],
            &["--json", "{}", "https://example.com"],
            &["-o", "file", "https://example.com"],
            &["-O", "https://example.com/file"],
        ];

        for args in ask_cmds {
            let result = check_network(&curl(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === wget ===

    #[test]
    fn test_wget_spider_allows() {
        let result = check_network(&wget(&["--spider", "https://example.com"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_wget_download_asks() {
        let ask_cmds = [
            &["https://example.com/file"][..],
            &["-O", "file", "https://example.com"],
            &["-r", "https://example.com"],
            &["-m", "https://example.com"],
        ];

        for args in ask_cmds {
            let result = check_network(&wget(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === rsync ===

    #[test]
    fn test_rsync_dry_run_allows() {
        let result = check_network(&rsync(&["-n", "src/", "dst/"]));
        assert_eq!(result.decision, Decision::Allow);

        let result = check_network(&rsync(&["--dry-run", "src/", "dst/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_rsync_sync_asks() {
        let result = check_network(&rsync(&["-av", "src/", "dst/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === netcat ===

    #[test]
    fn test_netcat_execute_blocked() {
        let result = check_network(&nc(&["-e", "/bin/bash", "host", "1234"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_netcat_sh_exec_blocked() {
        let result = check_network(&nc(&["-c", "/bin/bash", "host", "1234"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_netcat_exec_flag_blocked() {
        let result = check_network(&nc(&["--exec", "/bin/bash", "host", "1234"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_netcat_lua_exec_blocked() {
        let result = check_network(&nc(&["--lua-exec", "script.lua", "host", "1234"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_curl_form_string_asks() {
        let result = check_network(&curl(&["--form-string", "key=val", "https://example.com"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_curl_data_ascii_asks() {
        let result = check_network(&curl(&["--data-ascii", "data", "https://example.com"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_netcat_listen_asks() {
        let result = check_network(&nc(&["-l", "1234"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_netcat_connect_asks() {
        let result = check_network(&nc(&["host", "1234"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-network ===

    // === nmap ===

    #[test]
    fn test_nmap_asks() {
        let result = check_network(&make_cmd("nmap", &["-sV", "192.0.2.1"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_nmap_version_allows() {
        let result = check_network(&make_cmd("nmap", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === socat ===

    #[test]
    fn test_socat_asks() {
        let result = check_network(&make_cmd("socat", &["TCP:192.0.2.1:80", "STDOUT"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === telnet ===

    #[test]
    fn test_telnet_asks() {
        let result = check_network(&make_cmd("telnet", &["192.0.2.1", "80"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-network ===

    #[test]
    fn test_non_network_skips() {
        let result = check_network(&make_cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }

    // === github content URL guards (curl, xh) ===

    #[test]
    fn test_curl_github_raw_asks() {
        let urls = [
            "https://raw.githubusercontent.com/OWNER/REPO/main/f",
            "https://api.github.com/repos/OWNER/REPO/contents/p",
            "https://github.com/OWNER/REPO/blob/main/p",
            "https://github.com/OWNER/REPO/raw/main/p",
            "https://gist.githubusercontent.com/OWNER/ID/raw/HASH/f",
        ];
        for url in urls {
            let result = check_network(&curl(&[url]));
            assert_eq!(result.decision, Decision::Ask, "expected Ask for {url}");
            assert!(
                result.reason.as_deref().unwrap_or("").contains("gh api"),
                "reason should mention `gh api` for {url}"
            );
        }
    }

    #[test]
    fn test_curl_github_silent_follow_asks() {
        // Common in the wild: `curl -sL <url>` for fetching a raw file.
        let result = check_network(&curl(&[
            "-sL",
            "https://raw.githubusercontent.com/OWNER/REPO/main/f",
        ]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_curl_github_head_still_allows() {
        // HEAD is cheap and just checks reachability - no content leak.
        let result = check_network(&curl(&[
            "-I",
            "https://raw.githubusercontent.com/OWNER/REPO/main/f",
        ]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_curl_non_github_get_still_allows() {
        let result = check_network(&curl(&["https://example.com/path"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_curl_github_landing_page_allows() {
        // Non-content github.com landing pages are fine.
        let result = check_network(&curl(&["https://github.com/OWNER/REPO"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_xh_github_raw_asks() {
        let result = check_network(&make_cmd(
            "xh",
            &["https://raw.githubusercontent.com/OWNER/REPO/main/f"],
        ));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap_or("").contains("gh api"));
    }

    #[test]
    fn test_xh_get_subcommand_github_asks() {
        // `xh GET <url>` form.
        let result = check_network(&make_cmd(
            "xh",
            &["GET", "https://raw.githubusercontent.com/OWNER/REPO/main/f"],
        ));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_xh_non_github_allows() {
        let result = check_network(&make_cmd("xh", &["https://example.com/path"]));
        assert_eq!(result.decision, Decision::Allow);
    }
}
