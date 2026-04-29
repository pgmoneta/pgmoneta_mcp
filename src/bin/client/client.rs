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

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use inquire::Select;
use pgmoneta_mcp::configuration::{self, LlmConfiguration};
use pgmoneta_mcp::handler::PgmonetaHandler;
use pgmoneta_mcp::llm::{
    ChatMessage, LlmClient, LlmResponse, OllamaClient, OpenAiClient, ToolDefinition,
    mcp_tools_to_llm_schema,
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
    Cmd, Context as ReadlineContext, Editor, Helper, KeyCode, KeyEvent, Modifiers, Movement,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use tokio::runtime::Runtime;

const DEFAULT_CONF: &str = "/etc/pgmoneta-mcp/pgmoneta-mcp-client.conf";
const HISTORY_DIR: &str = ".pgmoneta-mcp";
const HISTORY_FILE: &str = "pgmoneta-mcp-client.history";
const HISTORY_MAX_ENTRIES: usize = 1000;
const CLIENT_NAME: &str = "pgmoneta MCP client";
const SLASH_COMMANDS: &[&str] = &["/developer", "/exit", "/help", "/quit", "/tools", "/user"];
const NATURAL_LANGUAGE_SYSTEM_PROMPT: &str = "\
You translate user requests into pgmoneta MCP tool invocations. \
Always select the single best matching tool from the provided tool list and respond with a tool call instead of plain text. \
Use arguments that are explicitly provided by the user and match the tool schema. \
Do not invent values. Omit optional arguments when the user did not specify them. \
If the user mentions a pgmoneta server name such as primary or standby, pass it through the tool's `server` argument. \
Requests to backup a server, such as `Backup primary server` will call the `backup_server` tool.";
const HELP_TEXT: &str = "\
Basic usage:
  /help                 Show this help
  /user                 User mode (default). Accept natural-language requests
  /developer            Developer mode. Accept <tool-name> {JSON} input and print full JSON responses
  /tools                List available MCP tools
  /exit or /quit        Exit the client

The client injects `username` from the users file automatically.
Required tool arguments such as `server` must be provided explicitly. If any
required arguments are missing, the client reports them before executing.

When an `[llm]` section is configured in `pgmoneta-mcp-client.conf`, you can
also enter natural-language requests such as `List backups on primary server`.
The client asks the LLM to select one of the tools from `/tools` and build the
matching JSON arguments before executing it.

Developer mode is intended for direct MCP/tool work. It expects explicit
`<tool-name> {JSON}` input and prints the full JSON response without the
human-readable translation used in user mode.

The input line supports readline-style history and editing shortcuts such as
arrow history navigation, Home/End, Ctrl+A/E, Ctrl+B/F, Ctrl+R, and Ctrl+U/K.
Command history is persisted in ~/.pgmoneta-mcp/pgmoneta-mcp-client.history.";

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
}

#[derive(Debug, PartialEq)]
enum ClientCommand {
    Help,
    UserMode,
    DeveloperMode,
    Tools,
    Exit,
    ToolCall {
        name: String,
        args: HashMap<String, Value>,
    },
    NaturalLanguage(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientDefaults {
    server: String,
    username: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientMode {
    User,
    Developer,
}

type ClientEditor = Editor<ClientHelper, DefaultHistory>;

#[derive(Default)]
struct ClientHelper;

enum ConfiguredLlm {
    Ollama(OllamaClient),
    OpenAi(OpenAiClient),
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

        if !is_slash_command_prefix(prefix) {
            return Ok((0, Vec::new()));
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

    fn hint(&self, _line: &str, _pos: usize, _ctx: &ReadlineContext<'_>) -> Option<Self::Hint> {
        None
    }
}

impl Highlighter for ClientHelper {}
impl Validator for ClientHelper {}
impl Helper for ClientHelper {}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = configuration::load_client_configuration(&args.conf)?;
    let llm = config
        .llm
        .as_ref()
        .map(ConfiguredLlm::from_configuration)
        .transpose()?;
    let defaults = ClientDefaults {
        server: tool_server_from_endpoint(&config.client.url)?,
        username: select_username(&args.users)?,
    };
    let prompt_target = prompt_target_from_url(&config.client.url, &defaults.username)?;
    let runtime = Runtime::new().context("Failed to create Tokio runtime")?;
    let client = match runtime.block_on(McpClient::connect(
        &config.client.url,
        config.client.timeout,
    )) {
        Ok(client) => client,
        Err(_) => {
            println!("{}", format_connect_error(&config.client.url));
            return Ok(());
        }
    };

    println!("{}", startup_banner(env!("CARGO_PKG_VERSION")));
    println!("• Help: /help");
    println!();

    let result = run_repl(&runtime, &client, &prompt_target, &defaults, llm.as_ref());
    runtime.block_on(client.cleanup())?;
    result
}

fn format_connect_error(url: &str) -> String {
    format!("No connection to {url}")
}

fn startup_banner(version: &str) -> String {
    let title = format!("{CLIENT_NAME} {version}");
    let width = title.len();
    let top_border = format!("┏{}┓", "━".repeat(width + 2));
    let bottom_border = format!("┗{}┛", "━".repeat(width + 2));

    let mut lines = Vec::with_capacity(3);
    lines.push(top_border);
    lines.push(format!("┃ {:width$} ┃", title, width = width));
    lines.push(bottom_border);
    lines.join("\n")
}

fn run_repl(
    runtime: &Runtime,
    client: &McpClient,
    prompt_target: &str,
    defaults: &ClientDefaults,
    llm: Option<&ConfiguredLlm>,
) -> Result<()> {
    let mut editor = ClientEditor::new().context("Failed to initialize line editor")?;
    editor.set_helper(Some(ClientHelper));
    configure_key_bindings(&mut editor);
    initialize_history(&mut editor)?;
    let mut mode = ClientMode::User;

    loop {
        let prompt = render_prompt(prompt_target, mode);
        match editor.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                editor
                    .add_history_entry(line)
                    .map_err(|e| anyhow!("Failed to add history entry: {}", e))?;
                save_history(&mut editor)?;

                if line.starts_with('/') {
                    match parse_input(line, &HashSet::new(), llm.is_some(), mode) {
                        Ok(ClientCommand::Help) => println!("{HELP_TEXT}"),
                        Ok(ClientCommand::UserMode) => {
                            mode = ClientMode::User;
                            println!("Switched to user mode.");
                        }
                        Ok(ClientCommand::DeveloperMode) => {
                            mode = ClientMode::Developer;
                            println!("Switched to developer mode.");
                        }
                        Ok(ClientCommand::Tools) => match runtime.block_on(client.list_tools()) {
                            Ok(tools) => println!("{}", format_tools(&tools)),
                            Err(error) => eprintln!("{}", format_runtime_error(&error)),
                        },
                        Ok(ClientCommand::Exit) => break,
                        Ok(_) => unreachable!("slash commands should not resolve to tool calls"),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                    continue;
                }

                let tools = match runtime.block_on(client.list_tools()) {
                    Ok(tools) => tools,
                    Err(error) => {
                        eprintln!("{}", format_runtime_error(&error));
                        continue;
                    }
                };
                let available_tools = tool_name_set(&tools);

                match parse_input(line, &available_tools, llm.is_some(), mode) {
                    Ok(ClientCommand::Help) => println!("{HELP_TEXT}"),
                    Ok(ClientCommand::UserMode) => {
                        mode = ClientMode::User;
                        println!("Switched to user mode.");
                    }
                    Ok(ClientCommand::DeveloperMode) => {
                        mode = ClientMode::Developer;
                        println!("Switched to developer mode.");
                    }
                    Ok(ClientCommand::Tools) => println!("{}", format_tools(&tools)),
                    Ok(ClientCommand::Exit) => break,
                    Ok(ClientCommand::ToolCall { name, args }) => execute_tool_command(
                        runtime,
                        client,
                        &mut editor,
                        &tools,
                        defaults,
                        mode,
                        name,
                        args,
                    )?,
                    Ok(ClientCommand::NaturalLanguage(request)) => {
                        let Some(llm) = llm else {
                            eprintln!(
                                "Error: Natural-language execution requires an [llm] section in the client configuration."
                            );
                            continue;
                        };

                        let llm_tools = mcp_tools_to_llm_schema(&tools);
                        match runtime
                            .block_on(translate_natural_language(llm, &llm_tools, &request))
                        {
                            Ok(ClientCommand::ToolCall { name, args }) => execute_tool_command(
                                runtime,
                                client,
                                &mut editor,
                                &tools,
                                defaults,
                                mode,
                                name,
                                args,
                            )?,
                            Ok(_) => unreachable!(
                                "natural-language translation must resolve to a tool call"
                            ),
                            Err(error) => eprintln!("{}", format_runtime_error(&error)),
                        }
                    }
                    Err(e) => eprintln!("Error: {e}"),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!();
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => return Err(anyhow!("Failed to read input: {}", e)),
        }
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

fn format_runtime_error(error: &anyhow::Error) -> String {
    format!("Error: {error}")
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

fn extract_text_content(result: &CallToolResult) -> Option<String> {
    let mut texts = Vec::with_capacity(result.content.len());

    for content in &result.content {
        let text = content.as_text()?;
        texts.push(text.text.as_str());
    }

    Some(texts.join("\n"))
}

fn format_text_response(text: &str) -> Result<String> {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => format_json_value(value, "JSON response"),
        Err(_) => Ok(text.to_string()),
    }
}

fn format_json_value(value: Value, label: &str) -> Result<String> {
    let value = humanize_json_value(normalize_json_value(value))?;
    if let Value::String(text) = value {
        return Ok(text);
    }
    if let Some(summary) = backup_response_summary(&value) {
        return Ok(summary);
    }
    if let Some(summary) = backup_list_summary(&value) {
        return Ok(summary);
    }
    if let Some(message) = empty_backups_message(&value) {
        return Ok(message);
    }
    format_pretty_json(&value, label)
}

fn humanize_json_value(value: Value) -> Result<Value> {
    let Value::Object(_) = &value else {
        return Ok(value);
    };

    let raw = serde_json::to_string(&value)
        .map_err(|e| anyhow!("Failed to serialize JSON response for translation: {}", e))?;

    match PgmonetaHandler::generate_call_tool_result_string(&raw) {
        Ok(translated) => serde_json::from_str(&translated).map_err(|e| {
            anyhow!(
                "Failed to parse translated JSON response from pgmoneta formatter: {}",
                e
            )
        }),
        Err(_) => Ok(value),
    }
}

fn empty_backups_message(value: &Value) -> Option<String> {
    if is_empty_backups_array(value.get("Backups")) {
        return Some("No backups available.".to_string());
    }

    if is_empty_backups_array(
        value
            .get("Response")
            .and_then(|response| response.get("Backups")),
    ) {
        return Some("No backups available.".to_string());
    }

    None
}

fn backup_list_summary(value: &Value) -> Option<String> {
    let command = value
        .get("Header")
        .and_then(|header| header.get("Command"))
        .and_then(Value::as_str);
    if command != Some("list-backup") {
        return None;
    }

    let response = value.get("Response")?.as_object()?;
    let backups = response.get("Backups")?.as_array()?;
    if backups.is_empty() {
        return None;
    }

    let server = response
        .get("Server")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let pgmoneta_version = response
        .get("ServerVersion")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let major = value_to_display_string(response.get("MajorVersion")?)?;
    let minor = value_to_display_string(response.get("MinorVersion")?)?;

    let mut lines = vec![format!(
        "{server} (pgmoneta {pgmoneta_version} w/ PostgreSQL {major}.{minor})"
    )];
    for backup in backups {
        let backup = backup.as_object()?;
        lines.push(format_backup_summary_line(backup)?);
    }

    Some(lines.join("\n"))
}

fn backup_response_summary(value: &Value) -> Option<String> {
    let command = value
        .get("Header")
        .and_then(|header| header.get("Command"))
        .and_then(Value::as_str);
    if command != Some("backup") {
        return None;
    }

    let response = value.get("Response")?.as_object()?;
    let server = response
        .get("Server")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let pgmoneta_version = response
        .get("ServerVersion")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let major = value_to_display_string(response.get("MajorVersion")?)?;
    let minor = value_to_display_string(response.get("MinorVersion")?)?;

    Some(format!(
        "{server} (pgmoneta {pgmoneta_version} w/ PostgreSQL {major}.{minor})\n{}",
        format_backup_summary_line(response)?
    ))
}

fn format_backup_summary_line(backup: &serde_json::Map<String, Value>) -> Option<String> {
    let backup_id = value_to_display_string(backup.get("Backup")?)?;

    let mut details = Vec::new();
    details.push(backup_kind_label(backup.get("Incremental")).to_string());
    if let Some(size) = backup.get("BackupSize").and_then(value_to_display_string) {
        details.push(format!("Backup: {size}"));
    }
    if let Some(size) = backup.get("RestoreSize").and_then(value_to_display_string) {
        details.push(format!("Restore: {size}"));
    }
    if let Some(validity) = backup_validity_label(backup.get("Valid")) {
        details.push(validity.to_string());
    }

    let suffix = if details.is_empty() {
        String::new()
    } else {
        format!(" | {}", details.join(", "))
    };
    Some(format!("• {backup_id}{suffix}"))
}

fn value_to_display_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
    }
}

fn backup_validity_label(value: Option<&Value>) -> Option<&'static str> {
    match value {
        Some(Value::Bool(true)) => Some("Valid"),
        Some(Value::Bool(false)) => Some("Invalid"),
        Some(Value::Number(number)) if number.as_u64() == Some(1) => Some("Valid"),
        Some(Value::Number(number)) if number.as_u64() == Some(0) => Some("Invalid"),
        Some(Value::String(text)) if text.eq_ignore_ascii_case("true") => Some("Valid"),
        Some(Value::String(text)) if text.eq_ignore_ascii_case("false") => Some("Invalid"),
        Some(Value::String(text)) if text == "1" => Some("Valid"),
        Some(Value::String(text)) if text == "0" => Some("Invalid"),
        _ => None,
    }
}

fn backup_kind_label(value: Option<&Value>) -> &'static str {
    match value {
        Some(Value::Bool(true)) => "Incremental",
        Some(Value::Number(number)) if number.as_u64() == Some(1) => "Incremental",
        Some(Value::String(text)) if text.eq_ignore_ascii_case("true") => "Incremental",
        Some(Value::String(text)) if text == "1" => "Incremental",
        _ => "Full",
    }
}

fn is_empty_backups_array(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(backups)) if backups.is_empty())
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
    llm_enabled: bool,
    mode: ClientMode,
) -> Result<ClientCommand> {
    let trimmed = input.trim();

    match trimmed {
        "/help" => Ok(ClientCommand::Help),
        "/user" => Ok(ClientCommand::UserMode),
        "/developer" => Ok(ClientCommand::DeveloperMode),
        "/tools" => Ok(ClientCommand::Tools),
        "/exit" | "/quit" => Ok(ClientCommand::Exit),
        _ if trimmed.starts_with('/') => Err(anyhow!("Unknown command '{}'", trimmed)),
        _ => parse_mode_input(trimmed, available_tools, llm_enabled, mode),
    }
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
                    "User mode requires an [llm] section in the client configuration."
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
) -> Result<()> {
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
            return Ok(());
        }
    }

    match runtime.block_on(client.call_tool(name, args)) {
        Ok(result) => match mode {
            ClientMode::User => println!("{}", format_tool_result(&result)?),
            ClientMode::Developer => println!("{}", format_tool_result_developer(&result)?),
        },
        Err(error) => eprintln!("{}", format_runtime_error(&error)),
    }

    Ok(())
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

async fn translate_natural_language<L: LlmClient>(
    llm: &L,
    tools: &[ToolDefinition],
    input: &str,
) -> Result<ClientCommand> {
    let messages = [
        ChatMessage::system(NATURAL_LANGUAGE_SYSTEM_PROMPT),
        ChatMessage::user(input),
    ];

    match llm.chat(&messages, tools).await? {
        LlmResponse::ToolCalls(tool_calls) => match tool_calls.as_slice() {
            [tool_call] => Ok(ClientCommand::ToolCall {
                name: tool_call.function.name.clone(),
                args: tool_call.function.arguments.clone(),
            }),
            [] => Err(anyhow!("LLM did not return a tool call for '{}'", input)),
            _ => Err(anyhow!(
                "LLM returned multiple tool calls for '{}'. Please be more specific.",
                input
            )),
        },
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

fn render_prompt(prompt_target: &str, mode: ClientMode) -> String {
    let suffix = match mode {
        ClientMode::User => '$',
        ClientMode::Developer => '#',
    };
    format!("{prompt_target}{suffix} ")
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

impl ConfiguredLlm {
    fn from_configuration(configuration: &LlmConfiguration) -> Result<Self> {
        match configuration.provider.to_lowercase().as_str() {
            "ollama" => Ok(Self::Ollama(OllamaClient::new(
                &configuration.endpoint,
                &configuration.model,
            ))),
            "llama.cpp" | "ramalama" | "vllm" => Ok(Self::OpenAi(OpenAiClient::new(
                &configuration.provider,
                &configuration.endpoint,
                &configuration.model,
            ))),
            _ => Err(anyhow!(
                "Unsupported LLM provider '{}'",
                configuration.provider
            )),
        }
    }
}

impl LlmClient for ConfiguredLlm {
    async fn chat(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse> {
        match self {
            Self::Ollama(client) => client.chat(messages, tools).await,
            Self::OpenAi(client) => client.chat(messages, tools).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{AnnotateAble, RawContent};
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
                name: "backup_server".to_string(),
                description: "Create a full backup".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "server": { "type": "string" }
                    }
                }),
            },
        }
    }

    #[test]
    fn test_parse_slash_commands() {
        let tools = HashSet::new();
        assert_eq!(
            parse_input("/help", &tools, false, ClientMode::User).unwrap(),
            ClientCommand::Help
        );
        assert_eq!(
            parse_input("/tools", &tools, false, ClientMode::User).unwrap(),
            ClientCommand::Tools
        );
        assert_eq!(
            parse_input("/quit", &tools, false, ClientMode::User).unwrap(),
            ClientCommand::Exit
        );
        assert_eq!(
            parse_input("/user", &tools, false, ClientMode::Developer).unwrap(),
            ClientCommand::UserMode
        );
        assert_eq!(
            parse_input("/developer", &tools, false, ClientMode::User).unwrap(),
            ClientCommand::DeveloperMode
        );
    }

    #[test]
    fn test_parse_tool_calls_in_developer_mode() {
        let tools = HashSet::from(["info".to_string(), "get_backup_info".to_string()]);

        assert_eq!(
            parse_input("info", &tools, false, ClientMode::Developer).unwrap(),
            ClientCommand::ToolCall {
                name: "info".to_string(),
                args: HashMap::new(),
            }
        );

        assert_eq!(
            parse_input(
                r#"get_backup_info {"server":"primary"}"#,
                &tools,
                false,
                ClientMode::Developer
            )
            .unwrap(),
            ClientCommand::ToolCall {
                name: "get_backup_info".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }
        );
    }

    #[test]
    fn test_parse_tool_calls_in_user_mode() {
        let tools = HashSet::from(["list_backups".to_string()]);

        assert_eq!(
            parse_input(
                r#"list_backups {"server":"primary"}"#,
                &tools,
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

        assert_eq!(
            parse_input(
                r#"list_backups {"server":"primary"}"#,
                &tools,
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
    fn test_parse_tool_call_rejects_non_object_args() {
        let tools = HashSet::from(["info".to_string()]);
        let err = parse_input("info []", &tools, false, ClientMode::Developer).unwrap_err();
        assert!(err.to_string().contains("JSON object"));
    }

    #[test]
    fn test_parse_input_treats_text_as_natural_language_in_user_mode() {
        let tools = HashSet::from(["list_backups".to_string()]);

        assert_eq!(
            parse_input(
                "List backups on primary server",
                &tools,
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

        let err = parse_input(
            "List backups on primary server",
            &tools,
            false,
            ClientMode::User,
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires an [llm]"));
    }

    #[test]
    fn test_parse_input_rejects_natural_language_in_developer_mode() {
        let tools = HashSet::from(["list_backups".to_string()]);

        let err = parse_input(
            "List backups on primary server",
            &tools,
            true,
            ClientMode::Developer,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Developer mode expects"));
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
    fn test_format_connect_error_uses_client_url() {
        assert_eq!(
            format_connect_error("http://localhost:8000/mcp"),
            "No connection to http://localhost:8000/mcp"
        );
    }

    #[test]
    fn test_startup_banner_contains_only_title() {
        let banner = startup_banner("0.2.1");

        assert!(banner.contains("pgmoneta MCP client 0.2.1"));
        assert!(!banner.contains("Server:"));
        assert!(!banner.contains("Username:"));
        assert!(!banner.contains("Help:"));
        assert!(banner.starts_with('┏'));
        assert!(banner.ends_with('┛'));
    }

    #[test]
    fn test_slash_completion_expands_unique_match() {
        let helper = ClientHelper;
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        let (start, matches) = helper.complete("/ex", 3, &context).unwrap();

        assert_eq!(start, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].replacement, "/exit");
    }

    #[test]
    fn test_slash_completion_lists_matching_commands() {
        let helper = ClientHelper;
        let history = DefaultHistory::new();
        let context = ReadlineContext::new(&history);

        let (_, matches) = helper.complete("/", 1, &context).unwrap();
        let replacements = matches
            .into_iter()
            .map(|candidate| candidate.replacement)
            .collect::<Vec<_>>();

        assert_eq!(
            replacements,
            vec!["/developer", "/exit", "/help", "/quit", "/tools", "/user"]
        );
    }

    #[test]
    fn test_slash_completion_ignores_non_command_inputs() {
        let helper = ClientHelper;
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
    fn test_format_runtime_error_prefixes_message() {
        let error = anyhow!("boom");
        assert_eq!(format_runtime_error(&error), "Error: boom");
    }

    #[test]
    fn test_format_tool_result_pretty_prints_json_text() {
        let result = CallToolResult::success(vec![
            RawContent::text(r#"{"Outcome":"Success","Count":2}"#).no_annotation(),
        ]);

        let formatted = format_tool_result(&result).unwrap();
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed, json!({"Outcome":"Success","Count":2}));
        assert!(formatted.contains('\n'));
        assert!(formatted.contains("    \""));
    }

    #[test]
    fn test_format_tool_result_humanizes_pgmoneta_json_text() {
        let result = CallToolResult::success(vec![
            RawContent::text(r#"{"Outcome":"Success","BackupSize":2048}"#).no_annotation(),
        ]);

        let formatted = format_tool_result(&result).unwrap();
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed, json!({"Outcome":"Success","BackupSize":"2.00 KB"}));
    }

    #[test]
    fn test_format_tool_result_returns_plain_text_when_not_json() {
        let result = CallToolResult::success(vec![
            RawContent::text("plain text response").no_annotation(),
        ]);

        assert_eq!(format_tool_result(&result).unwrap(), "plain text response");
    }

    #[test]
    fn test_format_tool_result_unquotes_json_string_text() {
        let result = CallToolResult::success(vec![
            RawContent::text(r#""Hello from pgmoneta MCP server!""#).no_annotation(),
        ]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            "Hello from pgmoneta MCP server!"
        );
    }

    #[test]
    fn test_format_tool_result_developer_keeps_json_string_quotes() {
        let result = CallToolResult::success(vec![
            RawContent::text(r#""Hello from pgmoneta MCP server!""#).no_annotation(),
        ]);

        assert_eq!(
            format_tool_result_developer(&result).unwrap(),
            "\"Hello from pgmoneta MCP server!\""
        );
    }

    #[test]
    fn test_format_tool_result_prefers_structured_content() {
        let result = CallToolResult::structured(json!({"status":"ok","count":1}));

        let formatted = format_tool_result(&result).unwrap();
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed, json!({"status":"ok","count":1}));
        assert!(formatted.contains('\n'));
        assert!(formatted.contains("    \""));
    }

    #[test]
    fn test_format_tool_result_humanizes_structured_pgmoneta_content() {
        let result = CallToolResult::structured(json!({"Outcome":"Success","BackupSize":1024}));

        let formatted = format_tool_result(&result).unwrap();
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed, json!({"Outcome":"Success","BackupSize":"1.00 KB"}));
    }

    #[test]
    fn test_format_tool_result_summarizes_backup_list_response() {
        let result = CallToolResult::success(vec![
            RawContent::text(
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
            )
            .no_annotation(),
        ]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            "primary (pgmoneta 0.21.0 w/ PostgreSQL 18.3)\n• 20260410142257 | Full, Backup: 8.45 MB, Restore: 8.44 MB, Valid"
        );
    }

    #[test]
    fn test_format_tool_result_summarizes_backup_response() {
        let result = CallToolResult::success(vec![
            RawContent::text(
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
            )
            .no_annotation(),
        ]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            "primary (pgmoneta 0.21.0 w/ PostgreSQL 18.3)\n• 20260412082050 | Full, Backup: 5.29 MB, Restore: 8.44 MB, Valid"
        );
    }

    #[test]
    fn test_format_tool_result_developer_preserves_full_json_response() {
        let result = CallToolResult::success(vec![
            RawContent::text(r#"{"Outcome":"Success","BackupSize":1024}"#).no_annotation(),
        ]);

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
    fn test_format_tool_result_reports_no_backups_for_empty_response_array() {
        let result = CallToolResult::success(vec![
            RawContent::text(r#"{"Outcome":"Success","Response":{"Backups":[]}}"#).no_annotation(),
        ]);

        assert_eq!(
            format_tool_result(&result).unwrap(),
            "No backups available."
        );
    }

    #[test]
    fn test_format_tool_result_unwraps_nested_json_string() {
        let result = CallToolResult::success(vec![
            RawContent::text(r#""{\"Header\":{\"Outcome\":\"Success\"}}""#).no_annotation(),
        ]);

        let formatted = format_tool_result(&result).unwrap();
        let parsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed, json!({"Header":{"Outcome":"Success"}}));
        assert!(formatted.contains("\n    \"Header\""));
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
            ClientCommand::ToolCall {
                name: "list_backups".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }
        );
    }

    #[tokio::test]
    async fn test_translate_natural_language_maps_backup_request_to_backup_tool() {
        let llm = MockLlm {
            response: LlmResponse::ToolCalls(vec![pgmoneta_mcp::llm::ToolCall {
                function: pgmoneta_mcp::llm::ToolCallFunction {
                    name: "backup_server".to_string(),
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
            ClientCommand::ToolCall {
                name: "backup_server".to_string(),
                args: HashMap::from([("server".to_string(), json!("primary"))]),
            }
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
}
