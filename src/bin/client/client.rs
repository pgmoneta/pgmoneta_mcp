// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod init;
mod markdown;
mod natural;
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use inquire::Select;
use pgmoneta_mcp::configuration::{self, LlmConfiguration};
use pgmoneta_mcp::llm::{
    ChatMessage, LlmClient, LlmResponse, OpenAiClient, ToolDefinition, mcp_tools_to_llm_schema,
};
use pgmoneta_mcp::mcp_client::McpClient;
use rmcp::model::{CallToolResult, Tool};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::{DefaultHistory, History};
use rustyline::validate::Validator;
use rustyline::{
    Cmd, ConditionalEventHandler, Context as ReadlineContext, Editor, Event, EventContext,
    EventHandler, Helper, KeyCode, KeyEvent, Modifiers, Movement, RepeatCount,
};
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

const DEFAULT_CONF: &str = "/etc/pgmoneta-mcp/pgmoneta-mcp-client.conf";
const HISTORY_DIR: &str = ".pgmoneta-mcp";
const HISTORY_FILE: &str = "pgmoneta-mcp-client.history";
const HISTORY_MAX_ENTRIES: usize = 1000;
const CTRL_C_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_NAME: &str = "pgmoneta MCP client";
const CLIENT_TITLE_LABEL: &str = "pgmoneta MCP/client";
const CLEAR_TERMINAL_SEQUENCE: &str = "\x1b[2J\x1b[H";
/// Clears the screen and the scrollback buffer, so only what is printed
/// afterwards (the status banner) remains.
const CLEAR_SCREEN_AND_SCROLLBACK_SEQUENCE: &str = "\x1b[H\x1b[2J\x1b[3J";
const CTRL_C_EXIT_MESSAGE: &str = "Press Ctrl+c again to quit";
const LOGO_ART_COLOR: &str = "\x1b[38;5;202m";
const ANSI_RESET: &str = "\x1b[0m";
const GHOST_TEXT_COLOR: &str = "\x1b[38;2;120;120;120m";
const CLIENT_LOGO_ART: &[&str] = &[
    " ▄▄▀███▄▄▄▄",
    "███▄▀ █████▄",
    "▀██████ ███▀",
    "███████▄▀█▀",
    " ██████▀█",
    "    ███▄",
    "    █▀▀▀",
];
const MODEL_COMMAND: &str = "/model";
const MODEL_COMMAND_PREFIX: &str = "/model ";
const SLASH_COMMANDS: &[&str] = &[
    "/clear",
    "/connect",
    "/developer",
    "/disconnect",
    "/exit",
    "/help",
    "/list-models",
    "/model",
    "/reload",
    "/quit",
    "/tools",
    "/user",
];
const NATURAL_LANGUAGE_SYSTEM_PROMPT: &str = "\
You translate user requests into pgmoneta MCP tool invocations. \
Always respond with tool calls from the provided tool list instead of plain text. \
If the request asks for a single operation, select the single best matching tool. \
If the request asks for several operations, return one tool call per operation, in the order the user asked for them. \
Use arguments that are explicitly provided by the user and match the tool schema. \
Do not invent values. Omit optional arguments when the user did not specify them. \
If the user mentions a pgmoneta server name such as primary or standby, pass it through the tool's `server` argument.";
const NATURAL_LANGUAGE_RENDER_SYSTEM_PROMPT: &str = "\
You are a response formatter for pgmoneta MCP client output. \
Given a user request, tool name, tool description, and raw JSON tool result, produce a concise, user-friendly markdown response. \
\
CRITICAL RULES: \
1. Read the JSON carefully. Output ALL data from it. Every field, every value. Do not omit, summarize, or skip any information. \
2. Restructure the JSON into clean markdown for readability, headings, bold labels, bullet points, or tables. \
3. The prompt contains the operation that was performed. Use that to write your opening line (e.g. \"Created a full backup on primary...\"). \
4. Bold the most important information with **info** (f.ex the last backup). \
5. Never start with generic preambles like \"The following backup history is available\" or \"Here is the result\". \
6. Never output raw JSON back to the user. \
7. Humanize raw numbers: \
   - Durations like \"00:00:2.2711\" → \"Completed in about 2 seconds\". \
   - \"00:01:15.5000\" → \"Completed in about 1 minute and 16 seconds\". \
   - \"01:30:00.0000\" → \"Completed in about 1 hour and 30 minutes\". \
   - File sizes like \"3.77 MB\" are already human-readable, keep them as-is. \
   - Timestamp IDs like 20260726011419 are identifiers, keep them as-is. \
   - Never reformat backup IDs. \
8. Never use emojis, icons, or unicode symbols (e.g. checkmarks, warning signs). Use plain text headings and labels only.";
const HELP_TEXT: &str = "\
Basic usage:
  /help                 Show this help
  /clear                Clear the screen, leaving only the status banner
  /connect [url]        Connect to [url] or the configured MCP server target
  /disconnect           Disconnect from the current MCP server target
  /reload               Reconnect with the original client URL and model configuration
  /user                 User mode (default). Accept natural-language requests
  /developer            Developer mode. Accept <tool-name> {JSON} input and print full JSON responses
  /list-models          List configured LLM profiles as name, model, and endpoint
  /model [name]         Show or switch the active LLM profile for natural-language requests
  /tools                List available MCP tools
  /exit or /quit        Exit the client
";

#[derive(Debug, Parser)]
#[command(
    name = "pgmoneta-mcp-client",
    about = "Interactive MCP client for pgmoneta",
    version
)]
struct Args {
    /// Path to pgmoneta MCP client configuration file
    #[arg(short = 'c', long, default_value = DEFAULT_CONF)]
    conf: String,

    /// Path to pgmoneta MCP users configuration file
    #[arg(
        short = 'u',
        long,
        default_value = "/etc/pgmoneta-mcp/pgmoneta-mcp-users.conf"
    )]
    users: String,

    /// Interactively create ~/.pgmoneta-mcp/pgmoneta-mcp-client.conf and exit.
    #[arg(short = 'i', long)]
    init: bool,
}

#[derive(Debug, PartialEq)]
enum ClientCommand {
    Help,
    Clear,
    Connect(Option<String>),
    Disconnect,
    Reload,
    ListModels,
    UserMode,
    DeveloperMode,
    Model(Option<String>),
    Tools,
    Exit,
    ToolCall {
        name: String,
        args: HashMap<String, Value>,
    },
    NaturalLanguage(String),
}

/// A tool invocation selected by the LLM for a natural-language request.
#[derive(Debug, Clone, PartialEq)]
struct PlannedToolCall {
    name: String,
    args: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientDefaults {
    server: String,
    username: String,
}

#[derive(Debug, Clone, Copy)]
struct ReplClientConfiguration<'a> {
    url: &'a str,
    timeout: u64,
    model: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientMode {
    User,
    Developer,
}

type ClientEditor = Editor<ClientHelper, DefaultHistory>;

struct ClientHelper {
    llm_names: Vec<String>,
    ghost: Arc<GhostState>,
}

/// Which of the ghost candidates is previewed. Shift+Tab advances `index`;
/// it starts over whenever the input line changes.
#[derive(Debug, Default)]
struct GhostState {
    index: AtomicUsize,
    last_input: Mutex<String>,
}

/// Tab accepts the ghost text (one word at a time for multi-word
/// natural-language forms) and otherwise falls back to normal completion.
struct AcceptGhostHandler;

/// Shift+Tab previews the next ghost candidate, and otherwise falls back to
/// normal backward completion.
struct CycleGhostHandler {
    ghost: Arc<GhostState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterruptAction {
    Continue,
    Exit,
}

#[derive(Debug, Default)]
struct InterruptState {
    last_interrupt: Option<Instant>,
}

impl ClientHelper {
    fn new(llm_names: Vec<String>) -> Self {
        Self {
            llm_names,
            ghost: Arc::new(GhostState::default()),
        }
    }

    /// Everything the part-typed `input` could still grow into, as the
    /// trailing characters that complete each candidate: slash commands,
    /// profile names after `/model ` (or `use model `), and the
    /// natural-language forms of the slash commands.
    fn ghost_candidates(&self, input: &str) -> Vec<String> {
        let suffixes = |candidates: &mut dyn Iterator<Item = &str>, prefix: &str| {
            candidates
                .filter(|candidate| candidate.starts_with(prefix) && candidate.len() > prefix.len())
                .map(|candidate| candidate[prefix.len()..].to_string())
                .collect::<Vec<_>>()
        };

        if is_slash_command_prefix(input) {
            return suffixes(&mut SLASH_COMMANDS.iter().copied(), input);
        }

        let model_prefix = model_completion_prefix(input)
            .map(|(_, prefix)| prefix)
            .or_else(|| {
                natural::natural_argument_prefix(input)
                    .filter(|(command, _, _)| *command == MODEL_COMMAND)
                    .map(|(_, _, prefix)| prefix)
            });
        if let Some(prefix) = model_prefix {
            let mut names = self
                .llm_names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            names.sort_unstable();
            return suffixes(&mut names.into_iter(), prefix);
        }

        natural::natural_language_ghost_candidates(input)
            .into_iter()
            .map(str::to_string)
            .collect()
    }
}

impl ConditionalEventHandler for AcceptGhostHandler {
    fn handle(
        &self,
        _evt: &Event,
        _n: RepeatCount,
        _positive: bool,
        ctx: &EventContext<'_>,
    ) -> Option<Cmd> {
        if ctx.pos() != ctx.line().len() {
            return None;
        }
        ctx.hint_text()
            .filter(|hint| !hint.is_empty())
            .map(|hint| Cmd::Insert(1, natural::first_ghost_word(hint).to_string()))
    }
}

impl ConditionalEventHandler for CycleGhostHandler {
    fn handle(
        &self,
        _evt: &Event,
        _n: RepeatCount,
        _positive: bool,
        ctx: &EventContext<'_>,
    ) -> Option<Cmd> {
        if !ctx.has_hint() {
            return None;
        }
        self.ghost.index.fetch_add(1, Ordering::Relaxed);
        Some(Cmd::Repaint)
    }
}

struct ClientTerminalTitleGuard;

impl ClientTerminalTitleGuard {
    fn new(command: &str) -> Self {
        set_client_terminal_title(Some(command));
        Self
    }
}

impl Drop for ClientTerminalTitleGuard {
    fn drop(&mut self) {
        set_client_terminal_title(None);
    }
}

impl InterruptState {
    fn reset(&mut self) {
        self.last_interrupt = None;
    }

    fn handle_interrupt(&mut self, now: Instant) -> InterruptAction {
        if let Some(last_interrupt) = self.last_interrupt
            && now.duration_since(last_interrupt) <= CTRL_C_EXIT_TIMEOUT
        {
            self.last_interrupt = None;
            return InterruptAction::Exit;
        }

        self.last_interrupt = Some(now);
        InterruptAction::Continue
    }
}

struct LlmStatusProbe {
    model: String,
    endpoint: String,
}

impl Completer for ClientHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &ReadlineContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let Some(prefix) = line.get(..pos) else {
            return Ok((0, Vec::new()));
        };

        if let Some((start, model_prefix)) = model_completion_prefix(prefix) {
            let mut matches = self
                .llm_names
                .iter()
                .filter(|name| name.starts_with(model_prefix))
                .map(|name| Pair {
                    display: name.clone(),
                    replacement: name.clone(),
                })
                .collect::<Vec<_>>();
            matches.sort_by(|left, right| left.replacement.cmp(&right.replacement));
            return Ok((start, matches));
        }

        if let Some((MODEL_COMMAND, start, model_prefix)) = natural::natural_argument_prefix(prefix)
        {
            let mut matches = self
                .llm_names
                .iter()
                .filter(|name| name.starts_with(model_prefix))
                .map(|name| Pair {
                    display: name.clone(),
                    replacement: name.clone(),
                })
                .collect::<Vec<_>>();
            matches.sort_by(|left, right| left.replacement.cmp(&right.replacement));
            return Ok((start, matches));
        }

        if !is_slash_command_prefix(prefix) {
            let matches = natural::natural_language_ghost_candidates(prefix)
                .into_iter()
                .map(|suffix| {
                    let phrase = format!("{prefix}{suffix}");
                    Pair {
                        display: phrase.trim_end().to_string(),
                        replacement: phrase,
                    }
                })
                .collect::<Vec<_>>();
            return Ok((0, matches));
        }

        let mut matches = SLASH_COMMANDS
            .iter()
            .filter(|command| command.starts_with(prefix))
            .map(|command| Pair {
                display: (*command).to_string(),
                replacement: (*command).to_string(),
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| left.replacement.cmp(&right.replacement));

        Ok((0, matches))
    }
}

impl Hinter for ClientHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &ReadlineContext<'_>) -> Option<Self::Hint> {
        if pos != line.len() {
            return None;
        }

        if let Ok(mut last_input) = self.ghost.last_input.lock()
            && *last_input != line
        {
            line.clone_into(&mut last_input);
            self.ghost.index.store(0, Ordering::Relaxed);
        }

        let candidates = self.ghost_candidates(line);
        if candidates.is_empty() {
            return None;
        }
        let index = self.ghost.index.load(Ordering::Relaxed) % candidates.len();
        candidates.into_iter().nth(index)
    }
}

impl Highlighter for ClientHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Borrowed(line)
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Owned(format!("{GHOST_TEXT_COLOR}{hint}{ANSI_RESET}"))
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        Cow::Borrowed(prompt)
    }
}
impl Validator for ClientHelper {}
impl Helper for ClientHelper {}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.init {
        return init::run_init();
    }
    let should_clear_terminal = io::stdout().is_terminal();
    let mut stdout = io::stdout();
    clear_startup_terminal(&mut stdout, should_clear_terminal)
        .context("Failed to clear terminal")?;
    let _ = pgmoneta_mcp::utils::Utility::write_terminal_title(
        &mut stdout,
        &client_console_title(None),
        should_clear_terminal,
    );
    let config = configuration::load_client_configuration(&args.conf)?;
    let llm_names = sorted_llm_names(&config.llms);
    let llm_probes = config
        .llms
        .iter()
        .map(|(name, configuration)| {
            (
                name.clone(),
                LlmStatusProbe {
                    model: configuration.model.clone(),
                    endpoint: configuration.endpoint.clone(),
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let llms = config
        .llms
        .iter()
        .map(|(name, configuration)| {
            (
                name.clone(),
                OpenAiClient::new(&configuration.endpoint, &configuration.model),
            )
        })
        .collect::<HashMap<_, _>>();
    let defaults = ClientDefaults {
        server: tool_server_from_endpoint(&config.client.url)?,
        username: select_username(&args.users)?,
    };
    let runtime = Runtime::new().context("Failed to create Tokio runtime")?;
    let client = runtime
        .block_on(McpClient::connect(
            &config.client.url,
            config.client.timeout,
        ))
        .ok();
    let active_model = default_model_name(&config.client.model).map(ToOwned::to_owned);
    let model_reachable = runtime.block_on(active_model_reachable(
        &llm_probes,
        active_model.as_deref(),
        config.client.timeout,
    ));

    print_status_header(
        env!("CARGO_PKG_VERSION"),
        &config.client.url,
        client.is_some(),
        active_model_endpoint(&llm_probes, active_model.as_deref()),
        active_model.as_deref(),
        model_reachable,
    );

    run_repl(
        &runtime,
        client,
        ReplClientConfiguration {
            url: &config.client.url,
            timeout: config.client.timeout,
            model: default_model_name(&config.client.model),
        },
        &defaults,
        &llms,
        &llm_probes,
        &llm_names,
        env!("CARGO_PKG_VERSION"),
        active_model,
    )
}

fn clear_screen_and_scrollback(output: &mut impl io::Write, is_terminal: bool) -> io::Result<()> {
    if !is_terminal {
        return Ok(());
    }

    output.write_all(CLEAR_SCREEN_AND_SCROLLBACK_SEQUENCE.as_bytes())?;
    output.flush()
}

fn clear_startup_terminal(output: &mut impl io::Write, is_terminal: bool) -> io::Result<()> {
    if !is_terminal {
        return Ok(());
    }

    output.write_all(CLEAR_TERMINAL_SEQUENCE.as_bytes())?;
    output.flush()
}

fn startup_banner(
    version: &str,
    client_url: &str,
    mcp_connected: bool,
    llm_endpoint: Option<&str>,
    model: Option<&str>,
    model_reachable: bool,
) -> String {
    let status_lines = [
        format!("{CLIENT_NAME} {version}"),
        String::new(),
        format!("MCP: {client_url} {}", connection_marker(mcp_connected)),
        format!(
            "LLM: {} {}",
            llm_endpoint.unwrap_or("none"),
            connection_marker(model_reachable)
        ),
        format!(
            "Model: {} {}",
            model_label(model),
            connection_marker(model_reachable)
        ),
        String::new(),
        "Help: /help".to_string(),
    ];
    let logo_width = CLIENT_LOGO_ART
        .iter()
        .map(|line| visible_width(line))
        .max()
        .unwrap_or(0);
    let status_width = status_lines
        .iter()
        .map(|line| visible_width(line))
        .max()
        .unwrap_or(0);
    let gap_width = 2;
    let width = logo_width + gap_width + status_width;
    let top_border = format!("┏{}┓", "━".repeat(width + 2));
    let bottom_border = format!("┗{}┛", "━".repeat(width + 2));

    let line_count = CLIENT_LOGO_ART.len().max(status_lines.len());
    let lines = (0..line_count)
        .map(|index| {
            let logo_line = CLIENT_LOGO_ART.get(index).copied().unwrap_or_default();
            let status_line = status_lines
                .get(index)
                .map(String::as_str)
                .unwrap_or_default();
            format_side_by_side_banner_line(logo_line, status_line, logo_width, gap_width, width)
        })
        .collect::<Vec<_>>();

    let mut banner = Vec::with_capacity(lines.len() + 2);
    banner.push(top_border);
    banner.extend(lines);
    banner.push(bottom_border);
    banner.join("\n")
}

fn format_side_by_side_banner_line(
    logo_line: &str,
    status_line: &str,
    logo_width: usize,
    gap_width: usize,
    width: usize,
) -> String {
    let logo_padding = logo_width.saturating_sub(visible_width(logo_line));
    let colored_logo_line = colorize_logo_art_line(logo_line);
    let content = format!(
        "{colored_logo_line}{}{status_line}",
        " ".repeat(logo_padding + gap_width)
    );
    let padding = width.saturating_sub(visible_width(&content));
    format!("┃ {content}{} ┃", " ".repeat(padding))
}

fn colorize_logo_art_line(line: &str) -> String {
    if line.trim().is_empty() {
        return line.to_string();
    }

    format!("{LOGO_ART_COLOR}{line}{ANSI_RESET}")
}

fn visible_width(text: &str) -> usize {
    strip_ansi_codes(text).chars().count()
}

fn strip_ansi_codes(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        output.push(ch);
    }

    output
}

fn run_repl(
    runtime: &Runtime,
    mut client: Option<McpClient>,
    repl_configuration: ReplClientConfiguration<'_>,
    defaults: &ClientDefaults,
    llms: &HashMap<String, OpenAiClient>,
    llm_probes: &HashMap<String, LlmStatusProbe>,
    llm_names: &[String],
    version: &str,
    mut active_model: Option<String>,
) -> Result<()> {
    let mut editor = ClientEditor::new().context("Failed to initialize line editor")?;
    editor.set_helper(Some(ClientHelper::new(llm_names.to_vec())));
    configure_key_bindings(&mut editor);
    initialize_history(&mut editor)?;
    let mut mode = ClientMode::User;
    let available_models = llm_name_set(llm_names);
    let mut current_client_url = repl_configuration.url.to_string();
    let mut interrupt_state = InterruptState::default();

    loop {
        let prompt = render_prompt(
            &display_prompt_target(&current_client_url, &defaults.username),
            mode,
        );
        match editor.readline(&prompt) {
            Ok(line) => {
                interrupt_state.reset();
                let Some(history_line) = history_entry(&line) else {
                    continue;
                };
                editor
                    .add_history_entry(history_line)
                    .map_err(|e| anyhow!("Failed to add history entry: {}", e))?;
                save_history(&mut editor)?;
                let line = line.trim();
                if is_comment_input(line) {
                    continue;
                }
                let translated = natural::translate_natural_language(line);
                let line = translated.as_deref().unwrap_or(line);

                if line.starts_with('/') {
                    match parse_input(
                        line,
                        &HashSet::new(),
                        &available_models,
                        active_model
                            .as_ref()
                            .and_then(|name| llms.get(name))
                            .is_some(),
                        mode,
                    ) {
                        Ok(ClientCommand::Help) => println!("{HELP_TEXT}"),
                        Ok(ClientCommand::Clear) => clear_and_print_header(
                            runtime,
                            llm_probes,
                            repl_configuration.timeout,
                            version,
                            &current_client_url,
                            client.is_some(),
                            active_model.as_deref(),
                        )?,
                        Ok(ClientCommand::Connect(connect_url)) => {
                            let model_reachable = runtime.block_on(active_model_reachable(
                                llm_probes,
                                active_model.as_deref(),
                                repl_configuration.timeout,
                            ));
                            current_client_url =
                                connect_url.unwrap_or_else(|| repl_configuration.url.to_string());
                            connect_client(
                                runtime,
                                &mut client,
                                &current_client_url,
                                repl_configuration.timeout,
                                version,
                                active_model_endpoint(llm_probes, active_model.as_deref()),
                                active_model.as_deref(),
                                model_reachable,
                            )?;
                        }
                        Ok(ClientCommand::Disconnect) => {
                            let model_reachable = runtime.block_on(active_model_reachable(
                                llm_probes,
                                active_model.as_deref(),
                                repl_configuration.timeout,
                            ));
                            disconnect_client(
                                runtime,
                                &mut client,
                                &current_client_url,
                                version,
                                active_model_endpoint(llm_probes, active_model.as_deref()),
                                active_model.as_deref(),
                                model_reachable,
                            )?;
                        }
                        Ok(ClientCommand::Reload) => reload_client(
                            runtime,
                            &mut client,
                            &mut current_client_url,
                            repl_configuration.url,
                            repl_configuration.timeout,
                            &mut active_model,
                            repl_configuration.model,
                            llm_probes,
                            version,
                        )?,
                        Ok(ClientCommand::ListModels) => {
                            println!("{}", format_list_models(llm_probes));
                        }
                        Ok(ClientCommand::UserMode) => {
                            mode = ClientMode::User;
                            println!("Switched to user mode.");
                        }
                        Ok(ClientCommand::DeveloperMode) => {
                            mode = ClientMode::Developer;
                            println!("Switched to developer mode.");
                        }
                        Ok(ClientCommand::Model(name)) => handle_model_command(
                            runtime,
                            &mut active_model,
                            name,
                            llm_probes,
                            repl_configuration.timeout,
                            llm_names,
                            version,
                            &current_client_url,
                            client.is_some(),
                        ),
                        Ok(ClientCommand::Tools) => {
                            let Some(active_client) = client.as_ref() else {
                                eprintln!("{}", disconnected_message());
                                continue;
                            };
                            match runtime.block_on(active_client.list_tools()) {
                                Ok(tools) => println!("{}", format_tools(&tools)),
                                Err(error) => eprintln!("{}", format_runtime_error(&error)),
                            }
                        }
                        Ok(ClientCommand::Exit) => break,
                        Ok(_) => unreachable!("slash commands should not resolve to tool calls"),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                    continue;
                }

                let _terminal_title_guard = ClientTerminalTitleGuard::new(line);

                let Some(active_client) = client.as_ref() else {
                    eprintln!("{}", disconnected_message());
                    continue;
                };

                let tools = match runtime.block_on(active_client.list_tools()) {
                    Ok(tools) => tools,
                    Err(error) => {
                        eprintln!("{}", format_runtime_error(&error));
                        continue;
                    }
                };
                let available_tools = tool_name_set(&tools);

                match parse_input(
                    line,
                    &available_tools,
                    &available_models,
                    active_model
                        .as_ref()
                        .and_then(|name| llms.get(name))
                        .is_some(),
                    mode,
                ) {
                    Ok(ClientCommand::Help) => println!("{HELP_TEXT}"),
                    Ok(ClientCommand::Clear) => clear_and_print_header(
                        runtime,
                        llm_probes,
                        repl_configuration.timeout,
                        version,
                        &current_client_url,
                        client.is_some(),
                        active_model.as_deref(),
                    )?,
                    Ok(ClientCommand::Connect(connect_url)) => {
                        let model_reachable = runtime.block_on(active_model_reachable(
                            llm_probes,
                            active_model.as_deref(),
                            repl_configuration.timeout,
                        ));
                        current_client_url =
                            connect_url.unwrap_or_else(|| repl_configuration.url.to_string());
                        connect_client(
                            runtime,
                            &mut client,
                            &current_client_url,
                            repl_configuration.timeout,
                            version,
                            active_model_endpoint(llm_probes, active_model.as_deref()),
                            active_model.as_deref(),
                            model_reachable,
                        )?;
                    }
                    Ok(ClientCommand::Disconnect) => {
                        let model_reachable = runtime.block_on(active_model_reachable(
                            llm_probes,
                            active_model.as_deref(),
                            repl_configuration.timeout,
                        ));
                        disconnect_client(
                            runtime,
                            &mut client,
                            &current_client_url,
                            version,
                            active_model_endpoint(llm_probes, active_model.as_deref()),
                            active_model.as_deref(),
                            model_reachable,
                        )?;
                    }
                    Ok(ClientCommand::Reload) => reload_client(
                        runtime,
                        &mut client,
                        &mut current_client_url,
                        repl_configuration.url,
                        repl_configuration.timeout,
                        &mut active_model,
                        repl_configuration.model,
                        llm_probes,
                        version,
                    )?,
                    Ok(ClientCommand::ListModels) => println!("{}", format_list_models(llm_probes)),
                    Ok(ClientCommand::UserMode) => {
                        mode = ClientMode::User;
                        println!("Switched to user mode.");
                    }
                    Ok(ClientCommand::DeveloperMode) => {
                        mode = ClientMode::Developer;
                        println!("Switched to developer mode.");
                    }
                    Ok(ClientCommand::Model(name)) => handle_model_command(
                        runtime,
                        &mut active_model,
                        name,
                        llm_probes,
                        repl_configuration.timeout,
                        llm_names,
                        version,
                        &current_client_url,
                        client.is_some(),
                    ),
                    Ok(ClientCommand::Tools) => println!("{}", format_tools(&tools)),
                    Ok(ClientCommand::Exit) => break,
                    Ok(ClientCommand::ToolCall { name, args }) => {
                        execute_tool_command(
                            runtime,
                            active_client,
                            &mut editor,
                            &tools,
                            defaults,
                            mode,
                            name,
                            args,
                            None,
                            None,
                        )?;
                    }
                    Ok(ClientCommand::NaturalLanguage(request)) => {
                        let Some(llm) = active_model.as_ref().and_then(|name| llms.get(name))
                        else {
                            eprintln!(
                                "Error: Natural-language execution requires a configured client LLM profile."
                            );
                            continue;
                        };

                        let llm_tools = mcp_tools_to_llm_schema(&tools);
                        match runtime
                            .block_on(translate_natural_language(llm, &llm_tools, &request))
                        {
                            Ok(tool_calls) => {
                                let total = tool_calls.len();
                                for (index, tool_call) in tool_calls.into_iter().enumerate() {
                                    if total > 1 {
                                        println!(
                                            "{}",
                                            format_tool_step_header(
                                                index + 1,
                                                total,
                                                &tool_call.name
                                            )
                                        );
                                    }
                                    let step_request = if total > 1 {
                                        format_step_request(index + 1, total, &tool_call.name)
                                    } else {
                                        request.clone()
                                    };

                                    let succeeded = execute_tool_command(
                                        runtime,
                                        active_client,
                                        &mut editor,
                                        &tools,
                                        defaults,
                                        mode,
                                        tool_call.name,
                                        tool_call.args,
                                        Some(&step_request),
                                        Some(llm),
                                    )?;
                                    if !succeeded {
                                        if index + 1 < total {
                                            eprintln!(
                                                "{}",
                                                format_skipped_steps_message(index + 1, total)
                                            );
                                        }
                                        break;
                                    }
                                }
                            }
                            Err(error) => eprintln!("{}", format_runtime_error(&error)),
                        }
                    }
                    Err(e) => eprintln!("Error: {e}"),
                }
            }
            Err(ReadlineError::Interrupted) => {
                match interrupt_state.handle_interrupt(Instant::now()) {
                    InterruptAction::Continue => {
                        println!("{CTRL_C_EXIT_MESSAGE}");
                        continue;
                    }
                    InterruptAction::Exit => break,
                }
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => return Err(anyhow!("Failed to read input: {}", e)),
        }
    }

    if let Some(active_client) = client {
        runtime.block_on(active_client.cleanup())?;
    }

    Ok(())
}

fn configure_key_bindings(editor: &mut ClientEditor) {
    editor.bind_sequence(
        KeyEvent(KeyCode::Home, Modifiers::NONE),
        Cmd::Move(Movement::BeginningOfLine),
    );
    editor.bind_sequence(
        KeyEvent(KeyCode::End, Modifiers::NONE),
        Cmd::Move(Movement::EndOfLine),
    );
    editor.bind_sequence(
        KeyEvent(KeyCode::Tab, Modifiers::NONE),
        EventHandler::Conditional(Box::new(AcceptGhostHandler)),
    );
    if let Some(ghost) = editor.helper().map(|helper| Arc::clone(&helper.ghost)) {
        editor.bind_sequence(
            KeyEvent(KeyCode::BackTab, Modifiers::NONE),
            EventHandler::Conditional(Box::new(CycleGhostHandler { ghost })),
        );
    }
}

fn initialize_history(editor: &mut ClientEditor) -> Result<()> {
    editor
        .history_mut()
        .set_max_len(HISTORY_MAX_ENTRIES)
        .map_err(|e| anyhow!("Failed to configure history length: {}", e))?;

    let history_path = history_path()?;
    if let Some(parent) = history_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create history directory '{}'", parent.display())
        })?;
    }
    if history_path.exists() {
        editor.load_history(&history_path).map_err(|e| {
            anyhow!(
                "Failed to load history from '{}': {}",
                history_path.display(),
                e
            )
        })?;
        editor
            .history_mut()
            .set_max_len(HISTORY_MAX_ENTRIES)
            .map_err(|e| anyhow!("Failed to trim loaded history: {}", e))?;
    }
    save_history(editor)?;

    Ok(())
}

fn save_history(editor: &mut ClientEditor) -> Result<()> {
    let history_path = history_path()?;
    if let Some(parent) = history_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create history directory '{}'", parent.display())
        })?;
    }

    editor.save_history(&history_path).map_err(|e| {
        anyhow!(
            "Failed to save history to '{}': {}",
            history_path.display(),
            e
        )
    })?;
    Ok(())
}

fn history_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(history_path_from_home(PathBuf::from(home)))
}

fn history_path_from_home(home: PathBuf) -> PathBuf {
    home.join(HISTORY_DIR).join(HISTORY_FILE)
}

fn is_slash_command_prefix(input: &str) -> bool {
    input.starts_with('/') && !input.chars().any(char::is_whitespace)
}

fn model_completion_prefix(input: &str) -> Option<(usize, &str)> {
    if let Some(model_prefix) = input.strip_prefix(MODEL_COMMAND_PREFIX)
        && !model_prefix.chars().any(char::is_whitespace)
    {
        return Some((MODEL_COMMAND_PREFIX.len(), model_prefix));
    }

    None
}

fn format_runtime_error(error: &anyhow::Error) -> String {
    format!("Error: {error}")
}

fn connection_marker(connected: bool) -> &'static str {
    if connected {
        "\u{1b}[32m✓\u{1b}[0m"
    } else {
        "\u{1b}[31m✗\u{1b}[0m"
    }
}

fn model_label(model: Option<&str>) -> &str {
    model.unwrap_or("none")
}

fn disconnected_message() -> &'static str {
    "Error: Not connected to the configured MCP server. Use /connect."
}

fn format_tool_result(result: &CallToolResult) -> Result<String> {
    if let Some(structured) = &result.structured_content {
        return format_json_value(structured.clone(), "structured response");
    }

    if let Some(text) = extract_text_content(result) {
        return format_text_response(&text);
    }

    format_pretty_json(result, "tool result")
}

fn format_tool_result_developer(result: &CallToolResult) -> Result<String> {
    if let Some(structured) = &result.structured_content {
        return format_pretty_json(
            &normalize_json_value(structured.clone()),
            "structured response",
        );
    }

    if let Some(text) = extract_text_content(result) {
        return match serde_json::from_str::<Value>(&text) {
            Ok(value) => format_pretty_json(&normalize_json_value(value), "JSON response"),
            Err(_) => Ok(text),
        };
    }

    format_pretty_json(result, "tool result")
}

fn format_metric_tool_result(result: &CallToolResult) -> Result<String> {
    let Some(text) = metric_tool_text(result) else {
        return format_tool_result(result);
    };

    if text.lines().count() > 1 {
        return Ok(text);
    }

    if let Some(value) = metric_sample_value(text.trim()) {
        return Ok(value.to_string());
    }

    Ok(text)
}

fn format_metric_tool_result_developer(result: &CallToolResult) -> Result<String> {
    let Some(text) = metric_tool_text(result) else {
        return format_tool_result_developer(result);
    };

    Ok(text)
}

/// Returns true when a tool call reached the server but the operation itself failed:
/// either the MCP result is flagged as an error, or pgmoneta reported `Outcome.Status: false`.
fn tool_result_failed(result: &CallToolResult) -> bool {
    if result.is_error == Some(true) {
        return true;
    }

    let value = match &result.structured_content {
        Some(structured) => structured.clone(),
        None => match extract_text_content(result)
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        {
            Some(value) => value,
            None => return false,
        },
    };

    // Some responses wrap the JSON object in a JSON string; unwrap one level.
    let value = match value {
        Value::String(inner) => match serde_json::from_str::<Value>(&inner) {
            Ok(value) => value,
            Err(_) => return false,
        },
        other => other,
    };

    value.pointer("/Outcome/Status").and_then(Value::as_bool) == Some(false)
}
fn extract_text_content(result: &CallToolResult) -> Option<String> {
    let mut texts = Vec::with_capacity(result.content.len());

    for content in &result.content {
        let text = content.as_text()?;
        texts.push(text.text.as_str());
    }

    Some(texts.join("\n"))
}

fn metric_tool_text(result: &CallToolResult) -> Option<String> {
    let text = extract_text_content(result)?;

    match serde_json::from_str::<Value>(&text) {
        Ok(Value::String(sample)) => Some(sample),
        _ => Some(text),
    }
}

fn format_text_response(text: &str) -> Result<String> {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => format_json_value(value, "JSON response"),
        Err(_) => Ok(text.to_string()),
    }
}

fn metric_sample_value(sample: &str) -> Option<&str> {
    pgmoneta_mcp::handler::metrics::split_metric_sample_line(sample)
        .ok()
        .and_then(|(_, value)| value.split_whitespace().next())
}

fn format_json_value(value: Value, _label: &str) -> Result<String> {
    let value = normalize_json_value(value);
    let value = compress_for_llm(value);
    Ok(serde_json::to_string(&value)?)
}

fn compress_for_llm(value: Value) -> Value {
    let Value::Object(mut map) = value else {
        return value;
    };

    let has_response = map.contains_key("Response");

    map.remove("Header");
    map.remove("Request");

    if has_response && let Some(Value::Object(outcome)) = map.get_mut("Outcome") {
        let status = outcome.remove("Status");
        if let Some(status) = status {
            outcome.insert(
                "Success".to_string(),
                Value::Bool(status == Value::Bool(true)),
            );
        }
    }
    Value::Object(map)
}

fn normalize_json_value(value: Value) -> Value {
    match value {
        Value::String(text) => match serde_json::from_str::<Value>(&text) {
            Ok(parsed) => normalize_json_value(parsed),
            Err(_) => Value::String(text),
        },
        Value::Array(values) => {
            Value::Array(values.into_iter().map(normalize_json_value).collect())
        }
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, normalize_json_value(value)))
                .collect(),
        ),
        primitive => primitive,
    }
}

fn format_pretty_json<T: Serialize>(value: &T, label: &str) -> Result<String> {
    let mut output = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut output, formatter);
    value
        .serialize(&mut serializer)
        .map_err(|e| anyhow!("Failed to serialize {}: {}", label, e))?;
    String::from_utf8(output).map_err(|e| anyhow!("Failed to encode {} as UTF-8: {}", label, e))
}

fn parse_input(
    input: &str,
    available_tools: &HashSet<String>,
    available_models: &HashSet<String>,
    llm_enabled: bool,
    mode: ClientMode,
) -> Result<ClientCommand> {
    let trimmed = input.trim();

    if let Some(command_name) = client_command_name(trimmed) {
        if command_name.starts_with('\\') {
            return Err(anyhow!("Unknown command '{}'", command_name));
        }

        return parse_slash_command(trimmed, command_name, available_models);
    }

    parse_mode_input(trimmed, available_tools, llm_enabled, mode)
}

fn parse_slash_command(
    input: &str,
    command_name: &str,
    available_models: &HashSet<String>,
) -> Result<ClientCommand> {
    match command_name {
        "/help" => parse_no_argument_slash_command(input, command_name, ClientCommand::Help),
        "/clear" => parse_no_argument_slash_command(input, command_name, ClientCommand::Clear),
        "/connect" => parse_connect_command(input),
        "/disconnect" => {
            parse_no_argument_slash_command(input, command_name, ClientCommand::Disconnect)
        }
        "/reload" => parse_no_argument_slash_command(input, command_name, ClientCommand::Reload),
        "/list-models" => {
            parse_no_argument_slash_command(input, command_name, ClientCommand::ListModels)
        }
        "/user" => parse_no_argument_slash_command(input, command_name, ClientCommand::UserMode),
        "/developer" => {
            parse_no_argument_slash_command(input, command_name, ClientCommand::DeveloperMode)
        }
        MODEL_COMMAND => {
            if input == MODEL_COMMAND {
                Ok(ClientCommand::Model(None))
            } else {
                parse_model_command(input, available_models)
            }
        }
        "/tools" => parse_no_argument_slash_command(input, command_name, ClientCommand::Tools),
        "/exit" | "/quit" => {
            parse_no_argument_slash_command(input, command_name, ClientCommand::Exit)
        }
        _ => Err(anyhow!("Unknown command '{}'", command_name)),
    }
}

fn client_command_name(input: &str) -> Option<&str> {
    let command_name = input.split_whitespace().next()?;
    (command_name.starts_with('/') || command_name.starts_with('\\')).then_some(command_name)
}

fn parse_no_argument_slash_command(
    input: &str,
    command_name: &str,
    command: ClientCommand,
) -> Result<ClientCommand> {
    if input == command_name {
        Ok(command)
    } else {
        bail!("Usage: {command_name}");
    }
}

fn is_comment_input(input: &str) -> bool {
    input.trim_start().starts_with('#')
}

fn history_entry(input: &str) -> Option<&str> {
    (!input.trim().is_empty()).then_some(input)
}

fn parse_connect_command(input: &str) -> Result<ClientCommand> {
    let Some(url) = input.strip_prefix("/connect") else {
        bail!("Missing connect command");
    };
    let url = url.trim();

    if url.is_empty() {
        return Ok(ClientCommand::Connect(None));
    }

    if url.split_whitespace().count() > 1 {
        bail!("Usage: /connect [url]");
    }

    Ok(ClientCommand::Connect(Some(url.to_string())))
}

fn parse_model_command(input: &str, available_models: &HashSet<String>) -> Result<ClientCommand> {
    let Some(name) = input.strip_prefix(MODEL_COMMAND_PREFIX) else {
        bail!("Missing model command");
    };
    let name = name.trim();

    if name.is_empty() {
        return Ok(ClientCommand::Model(None));
    }

    if available_models.contains(name) {
        return Ok(ClientCommand::Model(Some(name.to_string())));
    }

    if available_models.is_empty() {
        bail!("No LLM models are configured.");
    }

    let mut models = available_models.iter().cloned().collect::<Vec<_>>();
    models.sort();
    bail!(
        "Unknown model '{}'. Available models: {}",
        name,
        models.join(", ")
    )
}

fn parse_mode_input(
    input: &str,
    available_tools: &HashSet<String>,
    llm_enabled: bool,
    mode: ClientMode,
) -> Result<ClientCommand> {
    match mode {
        ClientMode::User => {
            if is_explicit_tool_call(input, available_tools) {
                parse_tool_call(input)
            } else if llm_enabled {
                Ok(ClientCommand::NaturalLanguage(input.to_string()))
            } else {
                Err(anyhow!(
                    "User mode requires a configured client LLM profile."
                ))
            }
        }
        ClientMode::Developer => {
            if is_explicit_tool_call(input, available_tools) {
                parse_tool_call(input)
            } else {
                let (name, _) = split_tool_call(input);
                Err(anyhow!(
                    "Developer mode expects '<tool-name> {{JSON}}'. Unknown tool '{}'. Use /tools to list tools.",
                    name
                ))
            }
        }
    }
}

fn is_explicit_tool_call(input: &str, available_tools: &HashSet<String>) -> bool {
    let (name, _) = split_tool_call(input);
    available_tools.contains(name)
}

fn parse_tool_call(input: &str) -> Result<ClientCommand> {
    let (name, raw_args) = split_tool_call(input);

    if name.is_empty() {
        bail!("Missing tool name");
    }

    let args = match raw_args {
        Some(raw) if !raw.is_empty() => parse_json_args(raw)?,
        _ => HashMap::new(),
    };

    Ok(ClientCommand::ToolCall {
        name: name.to_string(),
        args,
    })
}

fn split_tool_call(input: &str) -> (&str, Option<&str>) {
    if let Some(idx) = input.find(char::is_whitespace) {
        let (name, rest) = input.split_at(idx);
        (name, Some(rest.trim()))
    } else {
        (input, None)
    }
}

fn parse_json_args(raw_args: &str) -> Result<HashMap<String, Value>> {
    let value: Value = serde_json::from_str(raw_args)
        .with_context(|| format!("Arguments must be a valid JSON object: {}", raw_args))?;

    match value {
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err(anyhow!("Arguments must be a JSON object")),
    }
}

fn select_username(users_path: &str) -> Result<String> {
    let conf = configuration::load_user_configuration(users_path)?;
    let admins = conf
        .get("admins")
        .ok_or_else(|| anyhow!("Unable to find admins section in user configuration"))?;

    let mut usernames: Vec<String> = admins.keys().cloned().collect();
    usernames.sort();

    match usernames.len() {
        0 => bail!("No admin usernames found in '{}'", users_path),
        1 => Ok(usernames.remove(0)),
        _ => Select::new("Select admin username:", usernames)
            .prompt()
            .map_err(|e| anyhow!("Failed to select username from '{}': {}", users_path, e)),
    }
}

fn execute_tool_command(
    runtime: &Runtime,
    client: &McpClient,
    _editor: &mut ClientEditor,
    tools: &[Tool],
    defaults: &ClientDefaults,
    mode: ClientMode,
    name: String,
    args: HashMap<String, Value>,
    natural_language_request: Option<&str>,
    response_llm: Option<&OpenAiClient>,
) -> Result<bool> {
    let tool = tools
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| anyhow!("Unknown tool '{}'. Use /tools to list tools.", name))?;

    let args = match mode {
        ClientMode::User => sanitize_user_arguments(&tool.input_schema, args),
        ClientMode::Developer => args,
    };
    let args = apply_tool_defaults(&tool.input_schema, args, defaults);
    if mode == ClientMode::User {
        let missing = missing_required_arguments(&tool.input_schema, &args);
        if !missing.is_empty() {
            println!("{}", format_missing_required_arguments(&missing));
            return Ok(false);
        }
    }

    match runtime.block_on(client.call_tool(name.clone(), args)) {
        Ok(result) => {
            let failed = tool_result_failed(&result);
            match mode {
                ClientMode::User => {
                    let base_output = if name == "metric" {
                        format_metric_tool_result(&result)?
                    } else {
                        format_tool_result(&result)?
                    };

                    let output = if let (Some(request), Some(llm)) =
                        (natural_language_request, response_llm)
                    {
                        let tool_description = tool
                            .description
                            .as_ref()
                            .map(|desc| sanitize_tool_description(desc))
                            .filter(|desc| !desc.trim().is_empty())
                            .unwrap_or_else(|| "No description available.".to_string());
                        runtime
                            .block_on(postprocess_tool_output_markdown(
                                llm,
                                request,
                                &name,
                                &tool_description,
                                &base_output,
                            ))
                            .unwrap_or(base_output)
                    } else {
                        base_output
                    };
                    let output = ensure_user_mode_markdown_output(&output)?;
                    println!("{}", markdown::render_markdown_for_console(&output));
                }
                ClientMode::Developer => {
                    if name == "metric" {
                        println!("{}", format_metric_tool_result_developer(&result)?);
                    } else {
                        println!("{}", format_tool_result_developer(&result)?);
                    }
                }
            }
            if failed {
                return Ok(false);
            }
        }
        Err(error) => {
            eprintln!("{}", format_runtime_error(&error));
            return Ok(false);
        }
    }

    Ok(true)
}

fn format_tool_step_header(step: usize, total: usize, tool_name: &str) -> String {
    format!("Step {step}/{total}: {tool_name}")
}

fn format_skipped_steps_message(failed_step: usize, total: usize) -> String {
    let skipped = total - failed_step;
    let noun = if skipped == 1 { "step" } else { "steps" };
    format!("Step {failed_step}/{total} failed, skipping the remaining {skipped} {noun}.")
}

fn format_step_request(step: usize, total: usize, tool_name: &str) -> String {
    format!("Step {step} of {total} of a multi-step request: ran the {tool_name} tool.")
}

async fn postprocess_tool_output_markdown<T: LlmClient>(
    llm: &T,
    user_request: &str,
    tool_name: &str,
    tool_description: &str,
    tool_output: &str,
) -> Result<String> {
    let prompt =
        postprocess_tool_output_prompt(user_request, tool_name, tool_description, tool_output);

    match llm
        .chat(
            &[
                ChatMessage::system(NATURAL_LANGUAGE_RENDER_SYSTEM_PROMPT),
                ChatMessage::user(&prompt),
            ],
            &[],
        )
        .await?
    {
        LlmResponse::Text(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                bail!("LLM returned an empty rendered response")
            }
            if looks_like_json_output(trimmed) {
                bail!("LLM returned JSON instead of markdown")
            }
            Ok(trimmed.to_string())
        }
        LlmResponse::ToolCalls(_) => {
            bail!("LLM attempted tool calls while rendering final output")
        }
    }
}

fn postprocess_tool_output_prompt(
    user_request: &str,
    tool_name: &str,
    tool_description: &str,
    tool_output: &str,
) -> String {
    format!(
        "User request:\n{user_request}\n\nTool used:\n{tool_name}\n\nTool description:\n{tool_description}\n\nTool output:\n{tool_output}\n\nWrite the final user response in markdown."
    )
}

fn looks_like_json_output(text: &str) -> bool {
    if serde_json::from_str::<Value>(text).is_ok() {
        return true;
    }

    let trimmed = text.trim_start();
    trimmed.starts_with("```json") || trimmed.starts_with("```")
}

fn ensure_user_mode_markdown_output(output: &str) -> Result<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Ok(output.to_string());
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return format_json_value(value, "JSON response");
    }

    if let Some(json_block) = extract_json_code_block(trimmed)
        && let Ok(value) = serde_json::from_str::<Value>(json_block)
    {
        return format_json_value(value, "JSON response");
    }

    Ok(output.to_string())
}

fn extract_json_code_block(text: &str) -> Option<&str> {
    let start = text.find("```json")?;
    let after_tag = &text[start + "```json".len()..];
    let end = after_tag.find("```")?;
    Some(after_tag[..end].trim())
}

fn sanitize_user_arguments(
    schema: &serde_json::Map<String, Value>,
    args: HashMap<String, Value>,
) -> HashMap<String, Value> {
    let required = required_argument_set(schema);

    args.into_iter()
        .filter(|(name, value)| !should_drop_user_argument(name, value, &required))
        .collect()
}

fn should_drop_user_argument(name: &str, value: &Value, required: &HashSet<String>) -> bool {
    if required.contains(name) {
        return false;
    }

    match value {
        Value::Null => true,
        Value::String(text) => {
            let trimmed = text.trim();
            trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null")
        }
        _ => false,
    }
}

fn apply_tool_defaults(
    schema: &serde_json::Map<String, Value>,
    mut args: HashMap<String, Value>,
    defaults: &ClientDefaults,
) -> HashMap<String, Value> {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return args;
    };

    if properties.contains_key("username") {
        args.insert(
            "username".to_string(),
            Value::String(defaults.username.clone()),
        );
    }

    args
}

fn missing_required_arguments(
    schema: &serde_json::Map<String, Value>,
    args: &HashMap<String, Value>,
) -> Vec<String> {
    let mut missing: Vec<String> = required_argument_set(schema)
        .into_iter()
        .filter(|name| is_missing_required_argument(args.get(name)))
        .collect();
    missing.sort();
    missing
}

fn is_missing_required_argument(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null")
        }
        _ => false,
    }
}

fn format_missing_required_arguments(missing: &[String]) -> String {
    match missing {
        [] => String::new(),
        [name] => format!("Missing {name} definition"),
        _ => format!("Missing definitions: {}", missing.join(", ")),
    }
}

fn tool_server_from_endpoint(server: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(server)
        .with_context(|| format!("Invalid client server endpoint '{}'", server))?;
    parsed
        .host_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Client server endpoint '{}' is missing a host", server))
}

fn tool_name_set(tools: &[Tool]) -> HashSet<String> {
    tools.iter().map(|tool| tool.name.to_string()).collect()
}

fn llm_name_set(names: &[String]) -> HashSet<String> {
    names.iter().cloned().collect()
}

fn sorted_llm_names(llms: &HashMap<String, LlmConfiguration>) -> Vec<String> {
    let mut names = llms.keys().cloned().collect::<Vec<_>>();
    names.sort();
    names
}

fn default_model_name(model: &str) -> Option<&str> {
    let model = model.trim();
    if model.is_empty() { None } else { Some(model) }
}

fn handle_model_command(
    runtime: &Runtime,
    active_model: &mut Option<String>,
    name: Option<String>,
    llm_probes: &HashMap<String, LlmStatusProbe>,
    client_timeout: u64,
    llm_names: &[String],
    version: &str,
    client_url: &str,
    connected: bool,
) {
    match name {
        Some(name) => {
            *active_model = Some(name.clone());
            println!("Switched to model '{name}'.");
            let model_reachable = runtime.block_on(active_model_reachable(
                llm_probes,
                active_model.as_deref(),
                client_timeout,
            ));
            print_status_header(
                version,
                client_url,
                connected,
                active_model_endpoint(llm_probes, active_model.as_deref()),
                active_model.as_deref(),
                model_reachable,
            );
        }
        None => println!(
            "{}",
            format_model_status(active_model.as_deref(), llm_names)
        ),
    }
}

fn format_model_status(active_model: Option<&str>, llm_names: &[String]) -> String {
    if llm_names.is_empty() {
        return "No LLM models configured.".to_string();
    }

    let current = active_model.unwrap_or("none");
    format!(
        "Current model: {current}\nAvailable models: {}",
        llm_names.join(", ")
    )
}

fn format_list_models(llm_probes: &HashMap<String, LlmStatusProbe>) -> String {
    if llm_probes.is_empty() {
        return "No LLM models configured.".to_string();
    }

    let mut rows = llm_probes
        .iter()
        .map(|(name, probe)| (name.as_str(), probe.model.as_str(), probe.endpoint.as_str()))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.0.cmp(right.0));

    let name_header = "Name";
    let model_header = "Model";
    let endpoint_header = "Endpoint";

    let name_width = rows
        .iter()
        .map(|(name, _, _)| name.len())
        .max()
        .unwrap_or(0)
        .max(name_header.len());
    let model_width = rows
        .iter()
        .map(|(_, model, _)| model.len())
        .max()
        .unwrap_or(0)
        .max(model_header.len());
    let endpoint_width = rows
        .iter()
        .map(|(_, _, endpoint)| endpoint.len())
        .max()
        .unwrap_or(0)
        .max(endpoint_header.len());

    let mut lines = Vec::with_capacity(rows.len() + 2);
    lines.push(format!(
        "{name_header:<name_width$}  {model_header:<model_width$}  {endpoint_header:<endpoint_width$}",
    ));
    lines.push(format!(
        "{:-<name_width$}  {:-<model_width$}  {:-<endpoint_width$}",
        "", "", "",
    ));
    lines.extend(rows.into_iter().map(|(name, model, endpoint)| {
        format!("{name:<name_width$}  {model:<model_width$}  {endpoint:<endpoint_width$}",)
    }));
    lines.join("\n")
}

fn connect_client(
    runtime: &Runtime,
    client: &mut Option<McpClient>,
    client_url: &str,
    client_timeout: u64,
    version: &str,
    active_llm_endpoint: Option<&str>,
    active_model: Option<&str>,
    model_reachable: bool,
) -> Result<()> {
    if let Some(active_client) = client.take() {
        runtime.block_on(active_client.cleanup())?;
    }

    match runtime.block_on(McpClient::connect(client_url, client_timeout)) {
        Ok(active_client) => {
            *client = Some(active_client);
            print_status_header(
                version,
                client_url,
                true,
                active_llm_endpoint,
                active_model,
                model_reachable,
            );
        }
        Err(_) => {
            print_status_header(
                version,
                client_url,
                false,
                active_llm_endpoint,
                active_model,
                model_reachable,
            );
        }
    }
    Ok(())
}

fn reload_client(
    runtime: &Runtime,
    client: &mut Option<McpClient>,
    current_client_url: &mut String,
    configured_client_url: &str,
    client_timeout: u64,
    active_model: &mut Option<String>,
    configured_model: Option<&str>,
    llm_probes: &HashMap<String, LlmStatusProbe>,
    version: &str,
) -> Result<()> {
    *current_client_url = configured_client_url.to_string();
    *active_model = configured_model.map(ToOwned::to_owned);

    let model_reachable = runtime.block_on(active_model_reachable(
        llm_probes,
        active_model.as_deref(),
        client_timeout,
    ));

    connect_client(
        runtime,
        client,
        current_client_url,
        client_timeout,
        version,
        active_model_endpoint(llm_probes, active_model.as_deref()),
        active_model.as_deref(),
        model_reachable,
    )?;
    Ok(())
}

fn disconnect_client(
    runtime: &Runtime,
    client: &mut Option<McpClient>,
    client_url: &str,
    version: &str,
    active_llm_endpoint: Option<&str>,
    active_model: Option<&str>,
    model_reachable: bool,
) -> Result<()> {
    let Some(active_client) = client.take() else {
        println!("Already disconnected.");
        return Ok(());
    };

    runtime.block_on(active_client.cleanup())?;
    println!("Disconnected.");
    print_status_header(
        version,
        client_url,
        false,
        active_llm_endpoint,
        active_model,
        model_reachable,
    );
    Ok(())
}

fn clear_and_print_header(
    runtime: &Runtime,
    llm_probes: &HashMap<String, LlmStatusProbe>,
    client_timeout: u64,
    version: &str,
    client_url: &str,
    connected: bool,
    active_model: Option<&str>,
) -> Result<()> {
    let model_reachable = runtime.block_on(active_model_reachable(
        llm_probes,
        active_model,
        client_timeout,
    ));
    let mut stdout = io::stdout();
    let is_terminal = stdout.is_terminal();
    clear_screen_and_scrollback(&mut stdout, is_terminal).context("Failed to clear terminal")?;
    print_status_header(
        version,
        client_url,
        connected,
        active_model_endpoint(llm_probes, active_model),
        active_model,
        model_reachable,
    );
    Ok(())
}

fn active_model_endpoint<'a>(
    llm_probes: &'a HashMap<String, LlmStatusProbe>,
    active_model: Option<&str>,
) -> Option<&'a str> {
    active_model.and_then(|model| llm_probes.get(model).map(|probe| probe.endpoint.as_str()))
}

fn print_status_header(
    version: &str,
    client_url: &str,
    connected: bool,
    active_llm_endpoint: Option<&str>,
    active_model: Option<&str>,
    model_reachable: bool,
) {
    println!(
        "{}\n",
        startup_banner(
            version,
            client_url,
            connected,
            active_llm_endpoint,
            active_model,
            model_reachable
        )
    );
}

async fn active_model_reachable(
    llm_probes: &HashMap<String, LlmStatusProbe>,
    active_model: Option<&str>,
    timeout_secs: u64,
) -> bool {
    let Some(active_model) = active_model else {
        return false;
    };
    let Some(probe) = llm_probes.get(active_model) else {
        return false;
    };
    endpoint_reachable(&probe_urls(probe), timeout_secs).await
}

fn probe_urls(probe: &LlmStatusProbe) -> Vec<String> {
    let base = normalize_openai_compatible_endpoint(&probe.endpoint);
    vec![format!("{base}/health"), format!("{base}/v1/models")]
}

fn normalize_openai_compatible_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    endpoint.strip_suffix("/v1").unwrap_or(endpoint).to_string()
}

async fn endpoint_reachable(urls: &[String], timeout_secs: u64) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };

    for url in urls {
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => return true,
            _ => {}
        }
    }

    false
}

async fn translate_natural_language<L: LlmClient>(
    llm: &L,
    tools: &[ToolDefinition],
    input: &str,
) -> Result<Vec<PlannedToolCall>> {
    let messages = [
        ChatMessage::system(NATURAL_LANGUAGE_SYSTEM_PROMPT),
        ChatMessage::user(input),
    ];

    match llm.chat(&messages, tools).await? {
        LlmResponse::ToolCalls(tool_calls) => {
            if tool_calls.is_empty() {
                return Err(anyhow!("LLM did not return a tool call for '{}'", input));
            }

            // Validate every tool name before anything is executed, so a bad
            // call later in the list cannot leave the earlier calls half-applied.
            if let Some(unknown) = tool_calls.iter().find(|tool_call| {
                !tools
                    .iter()
                    .any(|tool| tool.function.name == tool_call.function.name)
            }) {
                return Err(anyhow!(
                    "LLM selected unknown tool '{}' for '{}'. Use /tools to list tools.",
                    unknown.function.name,
                    input
                ));
            }

            Ok(tool_calls
                .into_iter()
                .map(|tool_call| PlannedToolCall {
                    name: tool_call.function.name,
                    args: tool_call.function.arguments,
                })
                .collect())
        }
        LlmResponse::Text(text) => {
            let detail = text.trim();
            if detail.is_empty() {
                Err(anyhow!(
                    "LLM did not select a tool for '{}'. Please try rephrasing the request.",
                    input
                ))
            } else {
                Err(anyhow!("LLM did not select a tool: {}", detail))
            }
        }
    }
}

fn required_argument_set(schema: &serde_json::Map<String, Value>) -> HashSet<String> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn prompt_target_from_url(url: &str, username: &str) -> Result<String> {
    let parsed =
        reqwest::Url::parse(url).with_context(|| format!("Invalid client URL '{}'", url))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("Client URL '{}' is missing a host", url))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow!("Client URL '{}' is missing a port", url))?;
    let path = parsed.path();
    let query = parsed
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();

    Ok(format!("{username}@{host}:{port}{path}{query}"))
}

fn display_prompt_target(url: &str, username: &str) -> String {
    prompt_target_from_url(url, username).unwrap_or_else(|_| format!("{username}@{url}"))
}

fn render_prompt(prompt_target: &str, mode: ClientMode) -> String {
    let suffix = match mode {
        ClientMode::User => '$',
        ClientMode::Developer => '#',
    };
    format!("{prompt_target}{suffix} ")
}

fn client_console_title(command: Option<&str>) -> String {
    command
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .map(|command| {
            pgmoneta_mcp::utils::Utility::console_title(CLIENT_TITLE_LABEL, Some(command))
        })
        .unwrap_or_else(|| pgmoneta_mcp::utils::Utility::console_title(CLIENT_TITLE_LABEL, None))
}

fn set_client_terminal_title(command: Option<&str>) {
    let mut stdout = io::stdout();
    let is_terminal = stdout.is_terminal();
    let _ = pgmoneta_mcp::utils::Utility::write_terminal_title(
        &mut stdout,
        &client_console_title(command),
        is_terminal,
    );
}

fn format_tools(tools: &[Tool]) -> String {
    if tools.is_empty() {
        return "No tools available.".to_string();
    }

    let mut entries: Vec<&Tool> = tools.iter().collect();
    entries.sort_by_key(|tool| tool.name.to_string());

    let mut lines = vec![tools_intro().to_string()];
    for tool in entries {
        let description = tool
            .description
            .as_ref()
            .map(|desc| sanitize_tool_description(desc))
            .filter(|desc| !desc.trim().is_empty())
            .unwrap_or_else(|| "No description available.".to_string());
        lines.push(format!(
            "- {}{}: {}",
            tool.name,
            format_tool_arguments(&tool.input_schema),
            description
        ));
    }

    lines.join("\n")
}

fn tools_intro() -> &'static str {
    "Available tools:\n"
}

fn sanitize_tool_description(description: &str) -> String {
    description
        .replace(
            " The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
            "",
        )
        .replace(
            " The username has to be one of the pgmoneta admins to be able to perform this action.",
            "",
        )
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_tool_arguments(schema: &serde_json::Map<String, Value>) -> String {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return String::new();
    };

    let visible_properties: Vec<String> = properties
        .keys()
        .filter(|name| name.as_str() != "username")
        .cloned()
        .collect();

    if visible_properties.is_empty() {
        return String::new();
    }

    let required: HashSet<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();

    let mut names: Vec<String> = visible_properties;
    names.sort();

    let args = names
        .into_iter()
        .map(|name| {
            if required.contains(&name) {
                name
            } else {
                format!("{name}?")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!("({args})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ContentBlock;
    use rustyline::Context as ReadlineContext;
    use serde_json::json;

    struct MockLlm {
        response: LlmResponse,
    }

    impl LlmClient for MockLlm {
        async fn chat(
            &self,
            _messages: &[ChatMessage],
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse> {
            Ok(self.response.clone())
        }
    }

    fn sample_llm_tool_definition() -> ToolDefinition {
        ToolDefinition {
            tool_type: "function".to_string(),
            function: pgmoneta_mcp::llm::FunctionDefinition {
                name: "list_backups".to_string(),
                description: "List backups".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "server": { "type": "string" }
                    }
                }),
            },
        }
    }

    fn sample_backup_tool_definition() -> ToolDefinition {
        ToolDefinition {
            tool_type: "function".to_string(),
            function: pgmoneta_mcp::llm::FunctionDefinition {
                name: "backup".to_string(),
                description: "Create a full or incremental backup".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "server": { "type": "string" },
                        "backup_id": { "type": "string" }
                    }
                }),
            },
        }
    }

    fn sample_models() -> HashSet<String> {
        HashSet::from(["gemma".to_string(), "qwen".to_string()])
    }

    #[test]
    fn test_parse_slash_commands() {
        let tools = HashSet::new();
        let models = sample_models();
        assert_eq!(
            parse_input("/help", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::Help
        );
        assert_eq!(
            parse_input("/clear", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::Clear
        );
        assert_eq!(
            parse_input("/connect", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::Connect(None)
        );
        assert_eq!(
            parse_input(
                "/connect http://localhost:9000/mcp",
                &tools,
                &models,
                false,
                ClientMode::User
            )
            .unwrap(),
            ClientCommand::Connect(Some("http://localhost:9000/mcp".to_string()))
        );
        assert_eq!(
            parse_input("/disconnect", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::Disconnect
        );
        assert_eq!(
            parse_input("/reload", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::Reload
        );
        assert_eq!(
            parse_input("/list-models", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::ListModels
        );
        assert_eq!(
            parse_input("/tools", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::Tools
        );
        assert_eq!(
            parse_input("/quit", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::Exit
        );
        assert_eq!(
            parse_input("/user", &tools, &models, false, ClientMode::Developer).unwrap(),
            ClientCommand::UserMode
        );
        assert_eq!(
            parse_input("/developer", &tools, &models, false, ClientMode::User).unwrap(),
            ClientCommand::DeveloperMode
        );
        assert_eq!(
            parse_input("/model", &tools, &models, true, ClientMode::User).unwrap(),
            ClientCommand::Model(None)
        );
        assert_eq!(
            parse_input("/model qwen", &tools, &models, true, ClientMode::User).unwrap(),
            ClientCommand::Model(Some("qwen".to_string()))
        );
    }

    #[test]
    fn test_comment_input_uses_first_non_whitespace_character() {
        assert!(is_comment_input("# ignore this line"));
        assert!(is_comment_input("#/help"));
        assert!(is_comment_input(" # not a comment"));
        assert!(is_comment_input("\t\t# tab-indented comment"));
        assert!(!is_comment_input("list backups # inline note"));
        assert!(!is_comment_input(""));
    }

    #[test]
    fn test_history_entry_preserves_original_non_empty_input() {
        assert_eq!(history_entry("/tools"), Some("/tools"));
        assert_eq!(
            history_entry("      # My comment"),
            Some("      # My comment")
        );
        assert_eq!(history_entry("   "), None);
        assert_eq!(history_entry(""), None);
    }

    #[test]
    fn test_clear_startup_terminal_writes_escape_sequence_for_terminals() {
        let mut output = Vec::new();

        clear_startup_terminal(&mut output, true).unwrap();

        assert_eq!(output, CLEAR_TERMINAL_SEQUENCE.as_bytes());
    }

    #[test]
    fn test_clear_screen_and_scrollback_for_terminals() {
        let mut output = Vec::new();

        clear_screen_and_scrollback(&mut output, true).unwrap();

        assert_eq!(output, b"\x1b[H\x1b[2J\x1b[3J");
    }

    #[test]
    fn test_clear_screen_and_scrollback_skips_non_terminals() {
        let mut output = Vec::new();

        clear_screen_and_scrollback(&mut output, false).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn test_natural_language_clear_matches_slash_clear() {
        let models = sample_models();
        let command = natural::translate_natural_language("clear").unwrap();

        assert_eq!(
            parse_input(&command, &HashSet::new(), &models, true, ClientMode::User).unwrap(),
            ClientCommand::Clear
        );
    }

    #[test]
    fn test_clear_startup_terminal_skips_non_terminals() {
        let mut output = Vec::new();

        clear_startup_terminal(&mut output, false).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn test_parse_tool_calls_in_developer_mode() {
        let tools = HashSet::from(["info".to_string(), "get_info".to_string()]);
        let models = sample_models();

        assert_eq!(
            parse_input("info", &tools, &models, false, ClientMode::Developer).unwrap(),
            ClientCommand::ToolCall {
                name: "info".to_string(),
                args: HashMap::new(),
            }
        );

        assert_eq!(
            parse_input(
                r#"get_info {"server":"primary"}"#,
                &tools,
                &models,
                false,
                ClientMode::Developer
            )
            .unwrap(),
            ClientCommand::ToolCall {
                name: "get_info".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }
        );
    }

    #[test]
    fn test_parse_tool_calls_in_user_mode() {
        let tools = HashSet::from(["list_backups".to_string()]);
        let models = sample_models();

        assert_eq!(
            parse_input(
                r#"list_backups {"server":"primary"}"#,
                &tools,
                &models,
                true,
                ClientMode::User
            )
            .unwrap(),
            ClientCommand::ToolCall {
                name: "list_backups".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }
        );
    }

    #[test]
    fn test_parse_tool_calls_in_user_mode_without_llm() {
        let tools = HashSet::from(["list_backups".to_string()]);
        let models = sample_models();

        assert_eq!(
            parse_input(
                r#"list_backups {"server":"primary"}"#,
                &tools,
                &models,
                false,
                ClientMode::User
            )
            .unwrap(),
            ClientCommand::ToolCall {
                name: "list_backups".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }
        );
    }

    #[test]
    fn test_interrupt_requires_second_ctrl_c_within_timeout() {
        let mut interrupt_state = InterruptState::default();
        let now = Instant::now();

        assert_eq!(
            interrupt_state.handle_interrupt(now),
            InterruptAction::Continue
        );
        assert_eq!(
            interrupt_state.handle_interrupt(now + Duration::from_secs(1)),
            InterruptAction::Exit
        );
    }

    #[test]
    fn test_interrupt_resets_after_timeout() {
        let mut interrupt_state = InterruptState::default();
        let now = Instant::now();

        assert_eq!(
            interrupt_state.handle_interrupt(now),
            InterruptAction::Continue
        );
        assert_eq!(
            interrupt_state.handle_interrupt(now + Duration::from_secs(3)),
            InterruptAction::Continue
        );
    }

    #[test]
    fn test_interrupt_reset_clears_pending_exit() {
        let mut interrupt_state = InterruptState::default();
        let now = Instant::now();

        assert_eq!(
            interrupt_state.handle_interrupt(now),
            InterruptAction::Continue
        );
        interrupt_state.reset();
        assert_eq!(
            interrupt_state.handle_interrupt(now + Duration::from_secs(1)),
            InterruptAction::Continue
        );
    }

    #[test]
    fn test_parse_tool_call_rejects_non_object_args() {
        let tools = HashSet::from(["info".to_string()]);
        let models = sample_models();
        let err =
            parse_input("info []", &tools, &models, false, ClientMode::Developer).unwrap_err();
        assert!(err.to_string().contains("JSON object"));
    }

    #[test]
    fn test_parse_input_treats_text_as_natural_language_in_user_mode() {
        let tools = HashSet::from(["list_backups".to_string()]);
        let models = sample_models();

        assert_eq!(
            parse_input(
                "List backups on primary server",
                &tools,
                &models,
                true,
                ClientMode::User
            )
            .unwrap(),
            ClientCommand::NaturalLanguage("List backups on primary server".to_string())
        );
    }

    #[test]
    fn test_parse_input_reports_missing_llm_in_user_mode() {
        let tools = HashSet::from(["list_backups".to_string()]);
        let models = sample_models();

        let err = parse_input(
            "List backups on primary server",
            &tools,
            &models,
            false,
            ClientMode::User,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("requires a configured client LLM profile")
        );
    }

    #[test]
    fn test_parse_input_rejects_natural_language_in_developer_mode() {
        let tools = HashSet::from(["list_backups".to_string()]);
        let models = sample_models();

        let err = parse_input(
            "List backups on primary server",
            &tools,
            &models,
            true,
            ClientMode::Developer,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Developer mode expects"));
    }

    #[test]
    fn test_parse_model_command_rejects_unknown_name() {
        let err = parse_model_command("/model llama", &sample_models()).unwrap_err();
        assert!(err.to_string().contains("Unknown model 'llama'"));
    }

    #[test]
    fn test_parse_input_reports_unknown_slash_command_by_command_name() {
        let tools = HashSet::new();
        let models = sample_models();

        let err = parse_input("/q please", &tools, &models, false, ClientMode::User).unwrap_err();
        assert_eq!(err.to_string(), "Unknown command '/q'");
    }

    #[test]
    fn test_parse_input_rejects_backslash_commands_in_client() {
        let tools = HashSet::new();
        let models = sample_models();

        let err = parse_input(r"\q", &tools, &models, false, ClientMode::User).unwrap_err();
        assert_eq!(err.to_string(), "Unknown command '\\q'");
    }

    #[test]
    fn test_parse_input_reports_usage_for_known_slash_command_with_extra_arguments() {
        let tools = HashSet::new();
        let models = sample_models();

        let err = parse_input("/help now", &tools, &models, false, ClientMode::User).unwrap_err();
        assert_eq!(err.to_string(), "Usage: /help");
    }

    #[test]
    fn test_parse_connect_command_rejects_extra_arguments() {
        let err = parse_connect_command("/connect http://localhost:9000/mcp now").unwrap_err();
        assert_eq!(err.to_string(), "Usage: /connect [url]");
    }

    #[test]
    fn test_apply_tool_defaults_injects_username_only() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "server": { "type": "string" },
                "username": { "type": "string" },
                "backup_id": { "type": "string" }
            }
        }))
        .unwrap();
        let args = HashMap::from([("backup_id".to_string(), json!("latest"))]);
        let defaults = ClientDefaults {
            server: "primary".to_string(),
            username: "admin".to_string(),
        };

        let args = apply_tool_defaults(&schema, args, &defaults);
        assert_eq!(args.get("username").unwrap(), "admin");
        assert_eq!(args.get("backup_id").unwrap(), "latest");
        assert!(!args.contains_key("server"));
    }

    #[test]
    fn test_apply_tool_defaults_preserves_manual_server_and_overrides_username() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "server": { "type": "string" },
                "username": { "type": "string" }
            }
        }))
        .unwrap();
        let args = HashMap::from([
            ("server".to_string(), json!("primary")),
            ("username".to_string(), json!("other_user")),
        ]);
        let defaults = ClientDefaults {
            server: "derived".to_string(),
            username: "admin".to_string(),
        };

        let args = apply_tool_defaults(&schema, args, &defaults);
        assert_eq!(args.get("server").unwrap(), "primary");
        assert_eq!(args.get("username").unwrap(), "admin");
    }

    #[test]
    fn test_missing_required_arguments_reports_missing_server() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "server": { "type": "string" },
                "username": { "type": "string" }
            },
            "required": ["server", "username"]
        }))
        .unwrap();
        let args = HashMap::from([("username".to_string(), json!("admin"))]);

        assert_eq!(missing_required_arguments(&schema, &args), vec!["server"]);
        assert_eq!(
            format_missing_required_arguments(&missing_required_arguments(&schema, &args)),
            "Missing server definition"
        );
    }

    #[test]
    fn test_missing_required_arguments_reports_multiple_missing_fields() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "server": { "type": "string" },
                "backup_id": { "type": "string" }
            },
            "required": ["server", "backup_id"]
        }))
        .unwrap();
        let args = HashMap::new();

        assert_eq!(
            missing_required_arguments(&schema, &args),
            vec!["backup_id", "server"]
        );
        assert_eq!(
            format_missing_required_arguments(&missing_required_arguments(&schema, &args)),
            "Missing definitions: backup_id, server"
        );
    }

    #[test]
    fn test_sanitize_user_arguments_drops_optional_null_values() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "server": { "type": "string" },
                "sort": { "type": "string" }
            },
            "required": ["server"]
        }))
        .unwrap();
        let args = HashMap::from([
            ("server".to_string(), json!("primary")),
            ("sort".to_string(), Value::Null),
        ]);

        let args = sanitize_user_arguments(&schema, args);
        assert_eq!(args.get("server").unwrap(), "primary");
        assert!(!args.contains_key("sort"));
    }

    #[test]
    fn test_sanitize_user_arguments_drops_optional_null_strings() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "server": { "type": "string" },
                "sort": { "type": "string" }
            },
            "required": ["server"]
        }))
        .unwrap();
        let args = HashMap::from([
            ("server".to_string(), json!("primary")),
            ("sort".to_string(), json!(" null ")),
        ]);

        let args = sanitize_user_arguments(&schema, args);
        assert_eq!(args.get("server").unwrap(), "primary");
        assert!(!args.contains_key("sort"));
    }

    #[test]
    fn test_sanitize_user_arguments_keeps_required_strings() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "server": { "type": "string" }
            },
            "required": ["server"]
        }))
        .unwrap();
        let args = HashMap::from([("server".to_string(), json!(""))]);

        let args = sanitize_user_arguments(&schema, args);
        assert_eq!(args.get("server").unwrap(), "");
    }

    #[test]
    fn test_tool_server_from_endpoint_uses_host() {
        assert_eq!(
            tool_server_from_endpoint("http://localhost:8000/mcp").unwrap(),
            "localhost"
        );
        assert_eq!(
            tool_server_from_endpoint("https://example.com/mcp").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_prompt_target_from_url_formats_user_and_url_target() {
        assert_eq!(
            prompt_target_from_url("http://localhost:8080/mcp", "admin").unwrap(),
            "admin@localhost:8080/mcp"
        );
        assert_eq!(
            prompt_target_from_url("https://example.com/mcp", "alice").unwrap(),
            "alice@example.com:443/mcp"
        );
    }

    #[test]
    fn test_display_prompt_target_falls_back_to_raw_url() {
        assert_eq!(
            display_prompt_target("localhost:8080/mcp", "admin"),
            "admin@localhost:8080/mcp"
        );
    }

    #[test]
    fn test_render_prompt_uses_mode_specific_suffix() {
        assert_eq!(
            render_prompt("admin@localhost:8000/mcp", ClientMode::User),
            "admin@localhost:8000/mcp$ "
        );
        assert_eq!(
            render_prompt("admin@localhost:8000/mcp", ClientMode::Developer),
            "admin@localhost:8000/mcp# "
        );
    }

    #[test]
    fn test_client_console_title_uses_base_label_when_idle() {
        assert_eq!(client_console_title(None), "🟠 pgmoneta MCP/client");
        assert_eq!(client_console_title(Some("   ")), "🟠 pgmoneta MCP/client");
    }

    #[test]
    fn test_client_console_title_appends_current_command() {
        assert_eq!(
            client_console_title(Some("/tools")),
            "🟠 pgmoneta MCP/client — /tools"
        );
    }

    #[test]
    fn test_format_tool_arguments_marks_optional_fields() {
        let schema = serde_json::from_value(json!({
            "properties": {
                "backup": { "type": "string" },
                "server": { "type": "string" },
                "username": { "type": "string" }
            },
            "required": ["server", "username"]
        }))
        .unwrap();

        assert_eq!(format_tool_arguments(&schema), "(backup?, server)");
    }

    #[test]
    fn test_tools_intro_mentions_automatic_username_injection() {
        assert_eq!(tools_intro(), "Available tools:\n");
    }

    #[test]
    fn test_sanitize_tool_description_removes_username_boilerplate() {
        assert_eq!(
            sanitize_tool_description(
                "Create a full backup of a server. Requires a server name. The username has to be one of the pgmoneta admins to be able to access pgmoneta."
            ),
            "Create a full backup of a server. Requires a server name."
        );
        assert_eq!(
            sanitize_tool_description(
                "Shutdown the pgmoneta server. The username has to be one of the pgmoneta admins to be able to perform this action. Note: After pgmoneta is shut down, subsequent backup-related tool calls will fail until pgmoneta is restarted."
            ),
            "Shutdown the pgmoneta server. Note: After pgmoneta is shut down, subsequent backup-related tool calls will fail until pgmoneta is restarted."
        );
    }

    #[test]
    fn test_history_path_uses_pgmoneta_mcp_home_directory() {
        let path = history_path_from_home(PathBuf::from("/tmp/pgmoneta-home"));
        assert_eq!(
            path,
            PathBuf::from("/tmp/pgmoneta-home/.pgmoneta-mcp/pgmoneta-mcp-client.history")
        );
    }

    #[test]
    fn test_normalize_openai_compatible_endpoint_strips_v1_suffix() {
        assert_eq!(
            normalize_openai_compatible_endpoint("http://localhost:8100/v1"),
            "http://localhost:8100"
        );
        assert_eq!(
            normalize_openai_compatible_endpoint("http://localhost:8100/v1/"),
            "http://localhost:8100"
        );
        assert_eq!(
            normalize_openai_compatible_endpoint("http://localhost:8100"),
            "http://localhost:8100"
        );
    }

    #[test]
    fn test_probe_urls_use_v1_models_for_openai_compatible_endpoint() {
        let probe = LlmStatusProbe {
            model: "ggml-org/gemma-4-E4B-it-GGUF".to_string(),
            endpoint: "http://localhost:8100/v1".to_string(),
        };

        assert_eq!(
            probe_urls(&probe),
            vec![
                "http://localhost:8100/health".to_string(),
                "http://localhost:8100/v1/models".to_string()
            ]
        );
    }

    #[test]
    fn test_startup_banner_contains_title_mcp_and_model() {
        let banner = startup_banner(
            "0.3.0",
            "http://localhost:8000/mcp",
            false,
            Some("http://localhost:11434"),
            Some("qwen"),
            true,
        );

        let plain_banner = strip_ansi_codes(&banner);
        let banner_lines = plain_banner.lines().collect::<Vec<_>>();

        assert!(banner.contains("pgmoneta MCP client 0.3.0"));
        assert!(banner.contains("MCP: http://localhost:8000/mcp"));
        assert!(banner.contains("LLM: http://localhost:11434"));
        assert!(banner.contains("Model: qwen"));
        assert!(banner.contains("Help: /help"));
        assert!(plain_banner.contains("▄▄▀███▄▄▄▄"));
        assert!(banner_lines[1].contains("pgmoneta MCP client 0.3.0"));
        assert!(banner_lines[3].contains("MCP: http://localhost:8000/mcp"));
        assert!(banner_lines[4].contains("LLM: http://localhost:11434"));
        assert!(banner_lines[5].contains("Model: qwen"));
        assert!(banner_lines[7].contains("Help: /help"));
        assert!(banner_lines[1].contains('█'));
        assert!(banner_lines[2].contains('█'));
        assert!(banner_lines[3].contains('█'));
        assert!(banner_lines[4].contains('█'));
        assert!(banner_lines[5].contains('█'));
        assert!(banner_lines[6].contains('█'));
        assert!(banner_lines[7].contains('█'));
        assert!(banner.contains(connection_marker(false)));
        assert!(banner.contains(connection_marker(true)));
        assert!(banner.starts_with('┏'));
        assert!(banner.ends_with('┛'));
    }

    #[test]
    fn test_format_list_models_aligns_as_table() {
        let probes = HashMap::from([
            (
                "gemma".to_string(),
                LlmStatusProbe {
                    model: "ggml-org/gemma-4-E4B-it-GGUF".to_string(),
                    endpoint: "http://localhost:8100/v1".to_string(),
                },
            ),
            (
                "qwen".to_string(),
                LlmStatusProbe {
                    model: "qwen2.5:3b".to_string(),
                    endpoint: "http://localhost:11434".to_string(),
                },
            ),
        ]);

        assert_eq!(
            format_list_models(&probes),
            "Name   Model                         Endpoint                \n\
             -----  ----------------------------  ------------------------\n\
             gemma  ggml-org/gemma-4-E4B-it-GGUF  http://localhost:8100/v1\n\
             qwen   qwen2.5:3b                    http://localhost:11434  "
        );
    }

    #[test]
    fn test_startup_banner_aligns_visible_widths() {
        let banner = startup_banner(
            "0.3.0",
            "http://localhost:8000/mcp",
            false,
            Some("http://localhost:8100/v1"),
            Some("gemma-4-E4B-it-GGUF"),
            true,
        );

        let widths = banner.lines().map(strip_ansi_codes).collect::<Vec<_>>();
        let expected_width = widths[0].chars().count();
        assert!(
            widths
                .iter()
                .all(|line| line.chars().count() == expected_width)
        );
    }

    #[test]
    fn test_ghost_hint_completes_slash_commands() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        assert_eq!(helper.hint("/q", 2, &context).as_deref(), Some("uit"));
        assert_eq!(helper.hint("/quit", 5, &context), None);
        assert_eq!(helper.hint("/q", 1, &context), None);
        assert_eq!(helper.hint("", 0, &context), None);
    }

    #[test]
    fn test_ghost_hint_completes_natural_language_forms() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        assert_eq!(helper.hint("qu", 2, &context).as_deref(), Some("it"));
        assert_eq!(helper.hint("list t", 6, &context).as_deref(), Some("ools"));
        assert_eq!(
            helper.hint("use model q", 11, &context).as_deref(),
            Some("wen")
        );
        assert_eq!(
            helper.hint("/model g", 8, &context).as_deref(),
            Some("emma")
        );
        assert_eq!(helper.hint("list backups", 12, &context), None);
    }

    #[test]
    fn test_ghost_hint_cycles_and_resets_when_input_changes() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        assert_eq!(helper.hint("/d", 2, &context).as_deref(), Some("eveloper"));
        helper.ghost.index.fetch_add(1, Ordering::Relaxed);
        assert_eq!(helper.hint("/d", 2, &context).as_deref(), Some("isconnect"));
        helper.ghost.index.fetch_add(1, Ordering::Relaxed);
        assert_eq!(helper.hint("/d", 2, &context).as_deref(), Some("eveloper"));
        assert_eq!(helper.hint("/de", 3, &context).as_deref(), Some("veloper"));
        assert_eq!(helper.ghost.index.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_natural_language_completion() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        let (start, matches) = helper.complete("li", 2, &context).unwrap();
        assert_eq!(start, 0);
        assert_eq!(
            matches
                .into_iter()
                .map(|candidate| candidate.replacement)
                .collect::<Vec<_>>(),
            vec!["list models", "list tools"]
        );

        let (start, matches) = helper.complete("use model g", 11, &context).unwrap();
        assert_eq!(start, 10);
        assert_eq!(matches[0].replacement, "gemma");
    }

    #[test]
    fn test_natural_language_help_matches_slash_help() {
        let models = sample_models();
        let slash = parse_input("/help", &HashSet::new(), &models, true, ClientMode::User).unwrap();
        let natural = natural::translate_natural_language("help").unwrap();
        let natural =
            parse_input(&natural, &HashSet::new(), &models, true, ClientMode::User).unwrap();

        assert_eq!(slash, ClientCommand::Help);
        assert_eq!(natural, slash);
    }

    #[test]
    fn test_natural_language_quit_exits() {
        let models = sample_models();
        for input in ["quit", "exit", "bye", "QUIT"] {
            let command = natural::translate_natural_language(input).unwrap();
            assert_eq!(
                parse_input(&command, &HashSet::new(), &models, true, ClientMode::User).unwrap(),
                ClientCommand::Exit
            );
        }
    }

    #[test]
    fn test_help_documents_every_command() {
        for command in SLASH_COMMANDS {
            assert!(HELP_TEXT.contains(command), "{command} missing from help");
        }
    }

    #[test]
    fn test_slash_completion_expands_unique_match() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        let (start, matches) = helper.complete("/ex", 3, &context).unwrap();

        assert_eq!(start, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].replacement, "/exit");
    }

    #[test]
    fn test_slash_completion_lists_matching_commands() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        let (_, matches) = helper.complete("/", 1, &context).unwrap();
        let replacements = matches
            .into_iter()
            .map(|candidate| candidate.replacement)
            .collect::<Vec<_>>();

        assert_eq!(
            replacements,
            vec![
                "/clear",
                "/connect",
                "/developer",
                "/disconnect",
                "/exit",
                "/help",
                "/list-models",
                "/model",
                "/quit",
                "/reload",
                "/tools",
                "/user",
            ]
        );
    }

    #[test]
    fn test_disconnected_message_mentions_connect_command() {
        assert_eq!(
            disconnected_message(),
            "Error: Not connected to the configured MCP server. Use /connect."
        );
    }

    #[test]
    fn test_slash_completion_ignores_non_command_inputs() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        assert!(helper.complete("info", 4, &context).unwrap().1.is_empty());
        assert!(
            helper
                .complete("/help now", "/help now".len(), &context)
                .unwrap()
                .1
                .is_empty()
        );
    }

    #[test]
    fn test_model_completion_lists_matching_models() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        let (start, matches) = helper
            .complete("/model g", "/model g".len(), &context)
            .unwrap();
        let replacements = matches
            .into_iter()
            .map(|candidate| candidate.replacement)
            .collect::<Vec<_>>();

        assert_eq!(start, MODEL_COMMAND_PREFIX.len());
        assert_eq!(replacements, vec!["gemma"]);
    }

    #[test]
    fn test_model_completion_lists_all_models_after_space() {
        let helper = ClientHelper::new(vec!["gemma".to_string(), "qwen".to_string()]);
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        let (start, matches) = helper
            .complete(MODEL_COMMAND_PREFIX, MODEL_COMMAND_PREFIX.len(), &context)
            .unwrap();
        let replacements = matches
            .into_iter()
            .map(|candidate| candidate.replacement)
            .collect::<Vec<_>>();

        assert_eq!(start, MODEL_COMMAND_PREFIX.len());
        assert_eq!(replacements, vec!["gemma", "qwen"]);
    }

    #[test]
    fn test_format_runtime_error_prefixes_message() {
        let error = anyhow!("boom");
        assert_eq!(format_runtime_error(&error), "Error: boom");
    }

    #[test]
    fn test_format_tool_result_pretty_prints_json_text() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{"Outcome":"Success","Count":2}"#,
        )]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#"{"Count":2,"Outcome":"Success"}"#
        );
    }

    #[test]
    fn test_format_tool_result_humanizes_pgmoneta_json_text() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{"Outcome":"Success","BackupSize":2048}"#,
        )]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#"{"BackupSize":2048,"Outcome":"Success"}"#
        );
    }

    #[test]
    fn test_format_tool_result_returns_plain_text_when_not_json() {
        let result = CallToolResult::success(vec![ContentBlock::text("plain text response")]);

        assert_eq!(format_tool_result(&result).unwrap(), "plain text response");
    }

    #[test]
    fn test_format_tool_result_unquotes_json_string_text() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#""Hello from pgmoneta MCP server!""#,
        )]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#""Hello from pgmoneta MCP server!""#
        );
    }

    #[test]
    fn test_format_tool_result_developer_keeps_json_string_quotes() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#""Hello from pgmoneta MCP server!""#,
        )]);

        assert_eq!(
            format_tool_result_developer(&result).unwrap(),
            "\"Hello from pgmoneta MCP server!\""
        );
    }

    #[test]
    fn test_format_tool_result_prefers_structured_content() {
        let result = CallToolResult::structured(json!({"status":"ok","count":1}));

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#"{"count":1,"status":"ok"}"#
        );
    }

    #[test]
    fn test_format_tool_result_humanizes_structured_pgmoneta_content() {
        let result = CallToolResult::structured(json!({"Outcome":"Success","BackupSize":1024}));

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#"{"BackupSize":1024,"Outcome":"Success"}"#
        );
    }

    #[test]
    fn test_format_tool_result_summarizes_backup_list_response() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{
                "Header": {
                    "ClientVersion": "0.21.0",
                    "Command": "list-backup",
                    "Compression": "zstd",
                    "Encryption": "aes_256_gcm",
                    "Output": 1,
                    "Timestamp": 20260410151403
                },
                "Outcome": {
                    "Status": true,
                    "Time": "00:00:0.0160"
                },
                "Request": {
                    "Server": "primary",
                    "Sort": "asc"
                },
                "Response": {
                    "Backups": [
                        {
                            "Backup": 20260410142257,
                            "BackupSize": "8.45 MB",
                            "BiggestFileSize": "328.00 KB",
                            "Comments": null,
                            "Compression": 18,
                            "Encryption": "aes_256_gcm",
                            "Incremental": false,
                            "IncrementalParent": null,
                            "Keep": false,
                            "RestoreSize": "8.44 MB",
                            "Server": "primary",
                            "Valid": 1,
                            "WAL": 0
                        }
                    ],
                    "MajorVersion": 18,
                    "MinorVersion": 3,
                    "NumberOfBackups": 1,
                    "Server": "primary",
                    "ServerVersion": "0.21.0"
                }
            }"#,
        )]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#"{"Outcome":{"Success":true,"Time":"00:00:0.0160"},"Response":{"Backups":[{"Backup":20260410142257,"BackupSize":"8.45 MB","BiggestFileSize":"328.00 KB","Comments":null,"Compression":18,"Encryption":"aes_256_gcm","Incremental":false,"IncrementalParent":null,"Keep":false,"RestoreSize":"8.44 MB","Server":"primary","Valid":1,"WAL":0}],"MajorVersion":18,"MinorVersion":3,"NumberOfBackups":1,"Server":"primary","ServerVersion":"0.21.0"}}"#
        );
    }

    #[test]
    fn test_format_tool_result_summarizes_backup_response() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{
                "Header": {
                    "ClientVersion": "0.21.0",
                    "Command": "backup",
                    "Compression": "zstd",
                    "Encryption": "aes_256_gcm",
                    "Output": 1,
                    "Timestamp": 20260412082050
                },
                "Outcome": {
                    "Status": true,
                    "Time": "00:00:2.2711"
                },
                "Request": {
                    "Server": "primary"
                },
                "Response": {
                    "Backup": 20260412082050,
                    "BackupSize": "5.29 MB",
                    "BiggestFileSize": "328.00 KB",
                    "Compression": "zstd",
                    "Encryption": "aes_256_gcm",
                    "Incremental": false,
                    "IncrementalParent": "",
                    "MajorVersion": 18,
                    "MinorVersion": 3,
                    "RestoreSize": "8.44 MB",
                    "Server": "primary",
                    "ServerVersion": "0.21.0",
                    "Valid": 1
                }
            }"#,
        )]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#"{"Outcome":{"Success":true,"Time":"00:00:2.2711"},"Response":{"Backup":20260412082050,"BackupSize":"5.29 MB","BiggestFileSize":"328.00 KB","Compression":"zstd","Encryption":"aes_256_gcm","Incremental":false,"IncrementalParent":"","MajorVersion":18,"MinorVersion":3,"RestoreSize":"8.44 MB","Server":"primary","ServerVersion":"0.21.0","Valid":1}}"#
        );
    }

    #[test]
    fn test_format_tool_result_summarizes_incremental_backup_response_with_base() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{
                "Header": {
                    "Command": "backup"
                },
                "Response": {
                    "Backup": 20260725202010,
                    "BackupSize": "1.25 MB",
                    "Incremental": true,
                    "IncrementalParent": "20260725201041",
                    "MajorVersion": 18,
                    "MinorVersion": 1,
                    "RestoreSize": "6.20 MB",
                    "Server": "primary",
                    "ServerVersion": "0.22.0",
                    "Valid": 1
                }
            }"#,
        )]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            r#"{"Response":{"Backup":20260725202010,"BackupSize":"1.25 MB","Incremental":true,"IncrementalParent":20260725201041,"MajorVersion":18,"MinorVersion":1,"RestoreSize":"6.20 MB","Server":"primary","ServerVersion":"0.22.0","Valid":1}}"#
        );
    }

    #[test]
    fn test_format_tool_result_developer_preserves_full_json_response() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{"Outcome":"Success","BackupSize":1024}"#,
        )]);

        let formatted = format_tool_result_developer(&result).unwrap();
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed, json!({"Outcome":"Success","BackupSize":1024}));
        assert!(formatted.contains('\n'));
        assert!(formatted.contains("    \""));
    }

    #[test]
    fn test_format_tool_result_developer_pretty_prints_structured_content() {
        let result = CallToolResult::structured(json!({"status":"ok","count":1}));

        let formatted = format_tool_result_developer(&result).unwrap();
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed, json!({"status":"ok","count":1}));
        assert!(formatted.contains('\n'));
        assert!(formatted.contains("    \""));
    }

    #[test]
    fn test_format_metric_tool_result_extracts_value_for_user_mode() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"pgmoneta_version{version="0.22.0"} 1"#,
        )]);

        assert_eq!(format_metric_tool_result(&result).unwrap(), "1");
    }

    #[test]
    fn test_metric_sample_value_with_braces_in_label() {
        assert_eq!(
            metric_sample_value(r#"pgmoneta_query{q="select {x} from t"} 7"#),
            Some("7")
        );
    }

    #[test]
    fn test_format_metric_tool_result_preserves_multiple_metric_lines() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            "pgmoneta_retention_server{server=\"primary\"} 7\npgmoneta_retention_server{server=\"standby\"} 14",
        )]);

        assert_eq!(
            format_metric_tool_result(&result).unwrap(),
            "pgmoneta_retention_server{server=\"primary\"} 7\npgmoneta_retention_server{server=\"standby\"} 14"
        );
    }

    #[test]
    fn test_format_tool_result_developer_preserves_full_metric_line() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"pgmoneta_version{version="0.22.0"} 1"#,
        )]);

        assert_eq!(
            format_tool_result_developer(&result).unwrap(),
            r#"pgmoneta_version{version="0.22.0"} 1"#
        );
    }

    #[test]
    fn test_format_metric_tool_result_developer_unescapes_json_string_metric_line() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#""pgmoneta_version{version=\"0.22.0\"} 1""#,
        )]);

        assert_eq!(
            format_metric_tool_result_developer(&result).unwrap(),
            r#"pgmoneta_version{version="0.22.0"} 1"#
        );
    }

    #[test]
    fn test_format_tool_result_unwraps_nested_json_string() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#""{\"Header\":{\"Outcome\":\"Success\"}}""#,
        )]);

        assert_eq!(format_tool_result(&result).unwrap(), r#"{}"#);
    }

    #[tokio::test]
    async fn test_translate_natural_language_returns_tool_call() {
        let llm = MockLlm {
            response: LlmResponse::ToolCalls(vec![pgmoneta_mcp::llm::ToolCall {
                function: pgmoneta_mcp::llm::ToolCallFunction {
                    name: "list_backups".to_string(),
                    arguments: HashMap::from([("server".to_string(), json!("primary"))]),
                },
            }]),
        };

        let command = translate_natural_language(
            &llm,
            &[sample_llm_tool_definition()],
            "List backups on primary server",
        )
        .await
        .unwrap();

        assert_eq!(
            command,
            vec![PlannedToolCall {
                name: "list_backups".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }]
        );
    }

    #[tokio::test]
    async fn test_translate_natural_language_maps_backup_request_to_backup_tool() {
        let llm = MockLlm {
            response: LlmResponse::ToolCalls(vec![pgmoneta_mcp::llm::ToolCall {
                function: pgmoneta_mcp::llm::ToolCallFunction {
                    name: "backup".to_string(),
                    arguments: HashMap::from([("server".to_string(), json!("primary"))]),
                },
            }]),
        };

        let command = translate_natural_language(
            &llm,
            &[sample_backup_tool_definition()],
            "Backup primary server",
        )
        .await
        .unwrap();

        assert_eq!(
            command,
            vec![PlannedToolCall {
                name: "backup".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }]
        );
    }

    #[tokio::test]
    async fn test_translate_natural_language_returns_multiple_tool_calls_in_order() {
        let llm = MockLlm {
            response: LlmResponse::ToolCalls(vec![
                pgmoneta_mcp::llm::ToolCall {
                    function: pgmoneta_mcp::llm::ToolCallFunction {
                        name: "backup".to_string(),
                        arguments: HashMap::from([("server".to_string(), json!("primary"))]),
                    },
                },
                pgmoneta_mcp::llm::ToolCall {
                    function: pgmoneta_mcp::llm::ToolCallFunction {
                        name: "list_backups".to_string(),
                        arguments: HashMap::from([("server".to_string(), json!("primary"))]),
                    },
                },
            ]),
        };

        let command = translate_natural_language(
            &llm,
            &[
                sample_llm_tool_definition(),
                sample_backup_tool_definition(),
            ],
            "Backup primary server, then list its backups",
        )
        .await
        .unwrap();

        assert_eq!(
            command,
            vec![
                PlannedToolCall {
                    name: "backup".to_string(),
                    args: HashMap::from([("server".to_string(), json!("primary"))]),
                },
                PlannedToolCall {
                    name: "list_backups".to_string(),
                    args: HashMap::from([("server".to_string(), json!("primary"))]),
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_translate_natural_language_rejects_unknown_tool_in_multiple_calls() {
        let llm = MockLlm {
            response: LlmResponse::ToolCalls(vec![
                pgmoneta_mcp::llm::ToolCall {
                    function: pgmoneta_mcp::llm::ToolCallFunction {
                        name: "list_backups".to_string(),
                        arguments: HashMap::from([("server".to_string(), json!("primary"))]),
                    },
                },
                pgmoneta_mcp::llm::ToolCall {
                    function: pgmoneta_mcp::llm::ToolCallFunction {
                        name: "does_not_exist".to_string(),
                        arguments: HashMap::new(),
                    },
                },
            ]),
        };

        let err = translate_natural_language(
            &llm,
            &[sample_llm_tool_definition()],
            "List backups on primary, then do something unknown",
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("unknown tool 'does_not_exist'"));
    }

    #[tokio::test]
    async fn test_translate_natural_language_rejects_empty_tool_calls() {
        let llm = MockLlm {
            response: LlmResponse::ToolCalls(vec![]),
        };

        let err = translate_natural_language(
            &llm,
            &[sample_llm_tool_definition()],
            "List backups on primary server",
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("did not return a tool call"));
    }

    #[test]
    fn test_format_tool_step_header() {
        assert_eq!(
            format_tool_step_header(2, 3, "annotate_backup"),
            "Step 2/3: annotate_backup"
        );
    }

    #[test]
    fn test_format_step_request_mentions_only_current_step() {
        let prompt = format_step_request(1, 2, "annotate_backup");

        assert_eq!(
            prompt,
            "Step 1 of 2 of a multi-step request: ran the annotate_backup tool."
        );
    }

    #[test]
    fn test_tool_result_failed_detects_pgmoneta_outcome_failure() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{"Header":{"Command":"list-backup"},"Outcome":{"Error":"List backup: no server","Status":false,"Workflow":"main"},"Response":{"Server":"nosuchserver"}}"#,
        )]);

        assert!(tool_result_failed(&result));
    }

    #[test]
    fn test_tool_result_failed_accepts_successful_outcome() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{"Outcome":{"Status":true},"Response":{"Server":"primary"}}"#,
        )]);

        assert!(!tool_result_failed(&result));
    }

    #[test]
    fn test_tool_result_failed_unwraps_nested_json_string() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#""{\"Outcome\":{\"Status\":false}}""#,
        )]);

        assert!(tool_result_failed(&result));
    }

    #[test]
    fn test_tool_result_failed_ignores_plain_text() {
        let result = CallToolResult::success(vec![ContentBlock::text("pong")]);

        assert!(!tool_result_failed(&result));
    }

    #[test]
    fn test_format_skipped_steps_message() {
        assert_eq!(
            format_skipped_steps_message(1, 3),
            "Step 1/3 failed, skipping the remaining 2 steps."
        );
        assert_eq!(
            format_skipped_steps_message(2, 3),
            "Step 2/3 failed, skipping the remaining 1 step."
        );
    }

    #[tokio::test]
    async fn test_translate_natural_language_rejects_plain_text_response() {
        let llm = MockLlm {
            response: LlmResponse::Text("I think you should call list_backups".to_string()),
        };

        let err = translate_natural_language(
            &llm,
            &[sample_llm_tool_definition()],
            "List backups on primary server",
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("did not select a tool"));
    }

    #[test]
    fn test_postprocess_tool_output_prompt_includes_tool_description() {
        let prompt = postprocess_tool_output_prompt(
            "List backups on primary server",
            "list_backups",
            "List backups with sort control. Default sort is ascending.",
            "- 20260718173645 | Full | Valid",
        );

        assert!(prompt.contains("User request:\nList backups on primary server"));
        assert!(prompt.contains("Tool used:\nlist_backups"));
        assert!(prompt.contains(
            "Tool description:\nList backups with sort control. Default sort is ascending."
        ));
        assert!(prompt.contains("Tool output:\n- 20260718173645 | Full | Valid"));
        assert!(prompt.ends_with("Write the final user response in markdown."));
    }
}
