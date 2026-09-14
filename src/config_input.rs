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

use anyhow::{Context, Result, anyhow};
use rustyline::{
    Config, Context as RlContext, Editor, Helper,
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    history::DefaultHistory,
    validate::Validator,
};
use std::io::{self, Write};

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;

    let mut line = String::new();

    let read = io::stdin()
        .read_line(&mut line)
        .context("filed to read from standard input")?;

    if read == 0 {
        return Err(anyhow!("end of line reached"));
    }

    Ok(line.trim().to_string())
}

fn read_line(editor: &mut Editor<OptionCompleter, DefaultHistory>, prompt: &str) -> Result<String> {
    match editor.readline(prompt) {
        Ok(line) => Ok(line.trim().to_string()),
        Err(ReadlineError::Eof | ReadlineError::Interrupted) => {
            Err(anyhow!("aborted: reached end of input"))
        }
        Err(err) => Err(err.into()),
    }
}

pub fn prompt_required(label: &str) -> Result<String> {
    loop {
        let val = prompt(label)?;

        if !val.is_empty() {
            return Ok(val);
        }

        println!("value is required ");
    }
}

pub fn prompt_default(label: &str, default: &str) -> Result<String> {
    let val = prompt(&format!("{label} [{default}]"))?;

    if val.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(val)
    }
}

pub fn prompt_with_options_required(label: &str, options: &[&str]) -> Result<String> {
    let mut editor = options_editor(options)?;

    loop {
        let value = read_line(&mut editor, label)?;

        if options
            .iter()
            .any(|option| option.eq_ignore_ascii_case(&value))
        {
            return Ok(value);
        }

        println!(
            "'{value}' is not valid, choose one of {}",
            options.join(", ")
        )
    }
}

pub fn prompt_with_options(label: &str, default: &str, options: &[&str]) -> Result<String> {
    let mut editor = options_editor(options)?;

    loop {
        let value = read_line(&mut editor, &format!("{label} [{default}]: "))?;

        if value.is_empty() {
            return Ok(default.to_string());
        }

        if options
            .iter()
            .any(|option| option.eq_ignore_ascii_case(&value))
        {
            return Ok(value);
        }

        println!(
            "'{value}' is not valid, choose one of {}",
            options.join(", ")
        )
    }
}

pub fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    let default_label = if default { "Yes" } else { "No" };
    let mut editor = options_editor(&["Yes", "No"])?;
    loop {
        let value = read_line(
            &mut editor,
            &format!("{label} (Yes/No) [{default_label}]: "),
        )?;
        if value.is_empty() {
            return Ok(default);
        }
        match value.to_lowercase().as_str() {
            "yes" | "y" => return Ok(true),
            "no" | "n" => return Ok(false),
            _ => println!("Please answer Yes/Y or No/N."),
        }
    }
}

pub fn prompt_number<T>(label: &str, default: T) -> Result<T>
where
    T: std::str::FromStr + std::fmt::Display,
{
    loop {
        let value = prompt(&format!("{label} [{default}]: "))?;
        if value.is_empty() {
            return Ok(default);
        }
        match value.parse::<T>() {
            Ok(parsed) => return Ok(parsed),
            Err(_) => println!("'{value}' is not a valid whole number."),
        }
    }
}

fn options_editor(options: &[&str]) -> Result<Editor<OptionCompleter, DefaultHistory>> {
    let config = Config::builder()
        .completion_type(rustyline::CompletionType::List)
        .build();

    let mut editor: Editor<OptionCompleter, DefaultHistory> =
        rustyline::Editor::with_config(config)?;
    editor.set_helper(Some(OptionCompleter {
        options: options.iter().map(|s| s.to_string()).collect(),
    }));
    Ok(editor)
}

struct OptionCompleter {
    options: Vec<String>,
}

impl Completer for OptionCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &RlContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = line[..pos].to_lowercase();
        let matches = self
            .options
            .iter()
            .filter(|option| option.to_lowercase().starts_with(&prefix))
            .map(|option| Pair {
                display: option.clone(),
                replacement: option.clone(),
            })
            .collect();
        Ok((0, matches))
    }
}

impl Hinter for OptionCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &RlContext<'_>) -> Option<Self::Hint> {
        if pos != line.len() || line.is_empty() {
            return None;
        }
        let prefix = line.to_lowercase();
        self.options
            .iter()
            .find(|option| {
                option.to_lowercase().starts_with(&prefix) && !option.eq_ignore_ascii_case(line)
            })
            .map(|option| option[line.len()..].to_string())
            .filter(|suffix| !suffix.is_empty())
    }
}

impl Highlighter for OptionCompleter {}
impl Validator for OptionCompleter {}
impl Helper for OptionCompleter {}
