//! Rule-file deserialization schema shared by `build.rs` and the library.
//!
//! These types describe the structure of `rules/*.toml`. The build script
//! deserializes the TOML into these types to generate `src/generated/rules.rs`,
//! and the library reuses the same definitions so the two can never drift.
//!
//! `build.rs` pulls this module in via `#[path = "src/rules_schema.rs"]`, which
//! is why this file must stay free of any dependency on the rest of the crate.
//! It is compiled twice: once by the build script (before the lib crate exists)
//! and once as part of the library.
//!
//! The `schemars` dependency is only in `[dependencies]`, not
//! `[build-dependencies]`, so the build script cannot link it. Cargo DOES
//! propagate `feature = "schemars"` into the build-script compile, so gating
//! the `JsonSchema` derive on `feature = "schemars"` alone would make
//! `cargo build --features schemars` fail to compile the build script. The
//! `lib_only` cfg (emitted by `build.rs` via `cargo:rustc-cfg`) is set on the
//! library/binary compile but NOT on the build script's own compile, so the
//! `all(feature = "schemars", lib_only)` gate restricts every `schemars`
//! reference to the library where the crate is actually linkable.

use serde::{Deserialize, Serialize};

#[cfg(all(feature = "schemars", lib_only))]
use schemars::JsonSchema;

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct RuleFile {
    #[serde(default)]
    pub meta: RuleMeta,
    #[serde(default)]
    pub programs: Vec<ProgramRules>,
    #[serde(default)]
    pub safe_commands: Vec<String>,
    #[serde(default)]
    pub conditional_allow: Vec<ConditionalRule>,
    #[serde(default)]
    pub custom_handlers: Vec<CustomHandler>,
    /// Docs-only grouping of `safe_commands` into titled categories for the
    /// generated gate page. When non-empty, the generator renders a command
    /// grid (chips by category) instead of one allow rule-row per command, and
    /// omits the decision seg-bar and filter chips. Ignored at runtime; the
    /// runtime safe-command set is built from `safe_commands` alone. A test
    /// guards that every `safe_command` appears in exactly one group.
    #[serde(default)]
    pub command_groups: Vec<CommandGroup>,
}

/// One titled category in a docs command grid (see `RuleFile::command_groups`).
#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct CommandGroup {
    /// Category heading shown above the chip line (e.g. "Display & output").
    pub title: String,
    /// Commands listed under this category. Each must be a `safe_commands` entry.
    #[serde(default)]
    pub commands: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct RuleMeta {
    pub name: Option<String>,
    pub description: Option<String>,
    pub priority: Option<u32>,
    /// Brand prose paragraph rendered as `<p class="gate-lede">` after the
    /// summary on the generated gate page. HTML allowed (`<b>`, `<code>`,
    /// `<a>`); the generator passes it through verbatim.
    #[serde(default)]
    pub lede: Option<String>,
    /// Optional closing note rendered as `<p class="note">` (amber alert
    /// callout) after all rule cards. HTML allowed.
    #[serde(default)]
    pub note: Option<String>,
    /// Curated behavior tags appended to `gate-meta` after the auto-emitted
    /// `priority` and `unknown` tags. When non-empty, replaces the auto-emitted
    /// `custom handler <fn>` tags (which leak internal symbol names). HTML
    /// allowed for `<b>` and `<code>` inside each entry.
    #[serde(default)]
    pub behavior_tags: Vec<String>,
    /// Optional descriptive suffixes appended after `·` to the rule-card
    /// titles ("Allowed", "Asks first", "Blocked"). When unset, the bare
    /// title renders.
    #[serde(default)]
    pub card_titles: CardTitles,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct CardTitles {
    #[serde(default)]
    pub block: Option<String>,
    #[serde(default)]
    pub allow: Option<String>,
    #[serde(default)]
    pub ask: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ProgramRules {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub ask: Vec<AskRule>,
    #[serde(default)]
    pub block: Vec<BlockRule>,
    #[serde(default)]
    pub allow_if_flags: Vec<FlagOverride>,
    #[serde(default)]
    pub api_rules: Option<ApiRules>,
    #[serde(default)]
    pub default_allow: bool,
    #[serde(default)]
    pub unknown_action: UnknownAction,
    /// Docs-only catch-all reason. Shown on the synthesized "(all subcommands)"
    /// allow row the generator emits for an `unknown_action = "allow"` program
    /// that declares no explicit allow/ask/block rule (e.g. `pytest`, `jq`).
    /// Without it that row renders bare. Inert at runtime: `unknown_action`
    /// alone drives the allow decision.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum UnknownAction {
    #[default]
    Ask,
    Allow,
    Skip,
    Block,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    #[serde(default)]
    pub subcommand: Option<String>,
    #[serde(default)]
    pub subcommands: Vec<String>,
    #[serde(default)]
    pub subcommand_prefix: Option<String>,
    /// Check if args[1] (the "action" in commands like `aws <service> <action>`)
    /// starts with this prefix. Useful for AWS-style commands where the action
    /// is the second argument regardless of which service is used.
    #[serde(default)]
    pub action_prefix: Option<String>,
    #[serde(default)]
    pub unless_flags: Vec<String>,
    #[serde(default)]
    pub unless_args_contain: Vec<String>,
    #[serde(default)]
    pub if_flags_any: Vec<String>,
    /// Optional reason for allowing (shown in decision output)
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AskRule {
    #[serde(default)]
    pub subcommand: Option<String>,
    #[serde(default)]
    pub subcommands: Vec<String>,
    #[serde(default)]
    pub subcommand_prefix: Option<String>,
    /// Check if args[1] (the "action" in commands like `aws <service> <action>`)
    /// starts with this prefix. Useful for AWS-style commands where the action
    /// is the second argument regardless of which service is used.
    #[serde(default)]
    pub action_prefix: Option<String>,
    pub reason: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub warn: bool,
    #[serde(default)]
    pub if_flags: Vec<String>,
    #[serde(default)]
    pub if_flags_any: Vec<String>,
    /// If true, this ask rule should be auto-allowed in acceptEdits mode
    /// (when the command targets files within the allowed directories).
    #[serde(default)]
    pub accept_edits_auto_allow: bool,
    /// How this ask behaves under Claude Code auto mode.
    #[serde(default)]
    pub auto: AutoDisposition,
}

/// What an ask rule does when Claude Code is in auto mode.
///
/// Deferring lets the auto-mode classifier adjudicate with the full command
/// and conversation context, which is usually better than a static table.
/// Some actions are worth a guaranteed human decision anyway: the ones whose
/// blast radius is external and irreversible, where the classifier has no
/// more information than the rule does.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum AutoDisposition {
    /// Defer so the auto-mode classifier decides.
    #[default]
    Classifier,
    /// Hold an explicit ask that the classifier cannot bypass.
    Prompt,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BlockRule {
    #[serde(default)]
    pub subcommand: Option<String>,
    #[serde(default)]
    pub subcommands: Vec<String>,
    #[serde(default)]
    pub subcommand_prefix: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub if_args_contain: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct FlagOverride {
    pub flags_any: Vec<String>,
    #[serde(default)]
    pub for_subcommands: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ApiRules {
    pub trigger: String,
    #[serde(default)]
    pub method_flags: Vec<String>,
    #[serde(default)]
    pub safe_methods: Vec<String>,
    #[serde(default)]
    pub default_method: Option<String>,
    /// Flags that implicitly trigger POST (e.g., -f, --field for gh api)
    #[serde(default)]
    pub implicit_post_flags: Vec<String>,
    /// Endpoint prefixes that are always GET (e.g., "search/" for GitHub API)
    #[serde(default)]
    pub read_only_endpoints: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ConditionalRule {
    pub program: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub unless_flags: Vec<String>,
    #[serde(default)]
    pub on_flag_present: OnFlagAction,
    #[serde(default)]
    pub description: Option<String>,
    /// If true, this conditional ask should be auto-allowed in acceptEdits mode
    #[serde(default)]
    pub accept_edits_auto_allow: bool,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum OnFlagAction {
    #[default]
    Skip,
    Ask,
    Block,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct CustomHandler {
    pub program: String,
    pub handler: String,
    #[serde(default)]
    pub description: Option<String>,
}

// ============================================================================
// Security floor (rules/security.toml)
// ============================================================================
//
// The raw-string security floor is matched against the command text before AST
// parsing. Unlike the gates, it is not a per-program table: each row is a regex
// (or a Rust `handler`) plus a tier and a reason. `build.rs` generates a
// linear, first-match-wins `check_security_floor` from these rows, so file
// order is significant.

/// The tier a floor row resolves to. Encodes how the caller treats a hit:
/// `hard_ask` is force-promptable (not overridable by settings, promoted to
/// deny under auto mode); `soft_ask` is overridable via settings.json.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum FloorTier {
    HardAsk,
    SoftAsk,
}

/// Which scan-prepared input a floor row's regex runs against.
/// `quote_stripped` is comments-then-quotes stripped (the common case);
/// `comment_stripped` keeps quotes intact (needed by the substitution rows so
/// they can see inside `$(...)` / backticks).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum FloorScan {
    #[default]
    QuoteStripped,
    CommentStripped,
}

/// Special matching mode for a floor row. `command_substitution` iterates every
/// regex match, checks it against `inner_contains_any`, and echoes the matched
/// text (truncated) into the reason via the `{match}` placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum FloorWithin {
    CommandSubstitution,
}

/// The `rules/security.toml` file: an ordered list of floor patterns.
#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct SecurityFloorFile {
    #[serde(default)]
    pub meta: RuleMeta,
    #[serde(default)]
    pub patterns: Vec<SecurityPattern>,
}

/// One raw-string floor row. Exactly one of `regex` / `handler` drives matching:
/// `regex` rows run the compiled pattern (optionally in a `within` mode);
/// `handler` rows call a Rust function `crate::security_floor::<handler>` that
/// owns its own matching (the escape hatch for logic the table can't express,
/// mirroring the gates' `[[custom_handlers]]`).
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(all(feature = "schemars", lib_only), derive(JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct SecurityPattern {
    /// Stable kebab-case identifier. Doubles as the docs anchor and the regex
    /// static name (`FLOOR_<ID>_RE`).
    pub id: String,
    /// The regex source. `None` for `handler` rows (the handler owns matching).
    #[serde(default)]
    pub regex: Option<String>,
    pub tier: FloorTier,
    /// How a `soft_ask` row behaves under Claude Code auto mode. Ignored for
    /// `hard_ask` rows, which promote to deny there regardless.
    #[serde(default)]
    pub auto: AutoDisposition,
    /// Help-menu reason. For `within` rows it may contain a `{match}`
    /// placeholder replaced by the (truncated) matched substring.
    pub reason: String,
    #[serde(default)]
    pub scan: FloorScan,
    /// Cheap pre-guard: the scan input must contain at least one of these
    /// substrings before the regex runs (e.g. `["find ", "find\t"]`).
    #[serde(default)]
    pub requires_substring: Vec<String>,
    /// Special matching mode (see [`FloorWithin`]).
    #[serde(default)]
    pub within: Option<FloorWithin>,
    /// For `within` rows: the dangerous inner substrings a match must contain.
    #[serde(default)]
    pub inner_contains_any: Vec<String>,
    /// Names the values the reason interpolates. Only `["match"]` is supported,
    /// paired with a `{match}` placeholder in `reason`.
    #[serde(default)]
    pub reason_args: Vec<String>,
    /// Rust escape hatch: the name of a `crate::security_floor::<handler>`
    /// function that owns matching. Mutually exclusive with `regex`.
    #[serde(default)]
    pub handler: Option<String>,
}

impl AllowRule {
    pub fn subcommand_parts(&self) -> Vec<&str> {
        if let Some(ref s) = self.subcommand {
            s.split_whitespace().collect()
        } else if !self.subcommands.is_empty() {
            self.subcommands.iter().map(String::as_str).collect()
        } else {
            vec![]
        }
    }
}

impl AskRule {
    pub fn subcommand_parts(&self) -> Vec<&str> {
        if let Some(ref s) = self.subcommand {
            s.split_whitespace().collect()
        } else if !self.subcommands.is_empty() {
            self.subcommands.iter().map(String::as_str).collect()
        } else {
            vec![]
        }
    }
}

impl BlockRule {
    pub fn subcommand_parts(&self) -> Vec<&str> {
        if let Some(ref s) = self.subcommand {
            s.split_whitespace().collect()
        } else if !self.subcommands.is_empty() {
            self.subcommands.iter().map(String::as_str).collect()
        } else {
            vec![]
        }
    }
}
