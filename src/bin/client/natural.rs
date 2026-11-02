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

//! Natural-language forms of the client's slash commands (`quit` for `/quit`,
//! `list tools` for `/tools`, ...) and the grey inline "ghost" completion that
//! previews both the slash commands and these forms.

/// A natural-language phrase and the slash command it runs.
///
/// A phrase ending in a space takes exactly one argument token, which is
/// appended to the command (`use model gemma` -> `/model gemma`). A phrase
/// without a trailing space must match the whole input.
pub struct NaturalBinding {
    pub phrase: &'static str,
    pub command: &'static str,
}

const fn bind(phrase: &'static str, command: &'static str) -> NaturalBinding {
    NaturalBinding { phrase, command }
}

/// Every natural-language phrase, in priority order. The order is also the
/// order in which the ghost hint offers candidates and Shift+Tab cycles them.
///
/// Apart from `clear`, the phrases avoid bare MCP tool names such as `status`,
/// so those still reach the MCP server through the LLM. The `clear` tool stays
/// reachable as `clear {}` in developer mode or as a longer request in user
/// mode (e.g. `clear the prometheus statistics`).
pub const NATURAL_LANGUAGE_BINDINGS: &[NaturalBinding] = &[
    // --- help ---
    bind("help", "/help"),
    bind("show help", "/help"),
    bind("show commands", "/help"),
    // --- clear ---
    bind("clear", "/clear"),
    bind("clear screen", "/clear"),
    bind("clear terminal", "/clear"),
    // --- connect ---
    bind("connect", "/connect"),
    bind("connect to ", "/connect"),
    bind("connect ", "/connect"),
    // --- disconnect ---
    bind("disconnect", "/disconnect"),
    // --- reload ---
    bind("reload client", "/reload"),
    bind("reconnect", "/reload"),
    // --- user mode ---
    bind("user mode", "/user"),
    bind("switch to user mode", "/user"),
    // --- developer mode ---
    bind("developer mode", "/developer"),
    bind("switch to developer mode", "/developer"),
    // --- list models ---
    bind("list models", "/list-models"),
    bind("show models", "/list-models"),
    bind("models", "/list-models"),
    // --- model ---
    bind("show model", "/model"),
    bind("current model", "/model"),
    bind("model", "/model"),
    bind("use model ", "/model"),
    bind("switch to model ", "/model"),
    bind("model ", "/model"),
    // --- tools ---
    bind("list tools", "/tools"),
    bind("show tools", "/tools"),
    bind("tools", "/tools"),
    // --- exit ---
    bind("quit", "/quit"),
    bind("exit", "/exit"),
    bind("bye", "/quit"),
];

/// Translates a natural-language form into the slash command it stands for,
/// matching case-insensitively. Returns `None` for anything else, which is then
/// handled as before (an MCP tool call or a request for the LLM).
pub fn translate_natural_language(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() || input.starts_with('/') {
        return None;
    }

    for binding in NATURAL_LANGUAGE_BINDINGS {
        if !binding.phrase.ends_with(' ') {
            if binding.phrase.eq_ignore_ascii_case(input) {
                return Some(binding.command.to_string());
            }
            continue;
        }

        let Some(argument) = strip_prefix_ignore_ascii_case(input, binding.phrase) else {
            continue;
        };
        let argument = argument.trim();
        if !argument.is_empty() && !argument.chars().any(char::is_whitespace) {
            return Some(format!("{} {}", binding.command, argument));
        }
    }

    None
}

/// The slash command a phrase taking an argument resolves to, together with
/// the argument typed so far, when `input` is such a phrase followed by a
/// partial argument.
pub fn natural_argument_prefix(input: &str) -> Option<(&'static str, usize, &str)> {
    NATURAL_LANGUAGE_BINDINGS
        .iter()
        .filter(|binding| binding.phrase.ends_with(' '))
        .find_map(|binding| {
            let argument = strip_prefix_ignore_ascii_case(input, binding.phrase)?;
            (!argument.chars().any(char::is_whitespace)).then_some((
                binding.command,
                binding.phrase.len(),
                argument,
            ))
        })
}

/// Every natural-language phrase the part-typed `input` could still grow into,
/// as the trailing characters needed to complete each one. Empty input, slash
/// input and input that already spells a complete phrase yield nothing.
pub fn natural_language_ghost_candidates(input: &str) -> Vec<&'static str> {
    if input.is_empty() || input.starts_with('/') {
        return Vec::new();
    }
    if NATURAL_LANGUAGE_BINDINGS
        .iter()
        .any(|binding| binding.phrase.eq_ignore_ascii_case(input))
    {
        return Vec::new();
    }

    let mut seen: Vec<&str> = Vec::new();
    let mut candidates = Vec::new();
    for binding in NATURAL_LANGUAGE_BINDINGS {
        let phrase = binding.phrase;
        if strip_prefix_ignore_ascii_case(phrase, input).is_none() || phrase.len() <= input.len() {
            continue;
        }
        let suffix = &phrase[input.len()..];
        if suffix.trim().is_empty() {
            continue;
        }
        let key = phrase.trim_end();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        candidates.push(suffix);
    }
    candidates
}

/// The leading word of a ghost `suffix`, including the whitespace that trails
/// it, so Tab accepts a multi-word phrase one word at a time: for `"t tools"`
/// (completing `list tools`) this is `"t "`.
pub fn first_ghost_word(suffix: &str) -> &str {
    let Some(word_start) = suffix.find(|ch: char| !ch.is_whitespace()) else {
        return suffix;
    };
    let Some(relative_end) = suffix[word_start..].find(char::is_whitespace) else {
        return suffix;
    };
    let word_end = word_start + relative_end;
    let next = suffix[word_end..]
        .find(|ch: char| !ch.is_whitespace())
        .map(|index| word_end + index)
        .unwrap_or(suffix.len());
    &suffix[..next]
}

fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let head = input.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &input[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_bare_words() {
        assert_eq!(translate_natural_language("quit").as_deref(), Some("/quit"));
        assert_eq!(translate_natural_language("Exit").as_deref(), Some("/exit"));
        assert_eq!(
            translate_natural_language(" help ").as_deref(),
            Some("/help")
        );
        assert_eq!(
            translate_natural_language("list tools").as_deref(),
            Some("/tools")
        );
        assert_eq!(
            translate_natural_language("list models").as_deref(),
            Some("/list-models")
        );
    }

    #[test]
    fn test_translate_phrases_with_an_argument() {
        assert_eq!(
            translate_natural_language("use model gemma").as_deref(),
            Some("/model gemma")
        );
        assert_eq!(
            translate_natural_language("connect to http://localhost:8000/mcp").as_deref(),
            Some("/connect http://localhost:8000/mcp")
        );
    }

    #[test]
    fn test_translate_leaves_requests_for_the_llm_alone() {
        assert_eq!(translate_natural_language("list backups on primary"), None);
        assert_eq!(translate_natural_language("use model gemma please"), None);
        assert_eq!(translate_natural_language("clear {}"), None);
        assert_eq!(
            translate_natural_language("clear the prometheus statistics"),
            None
        );
        assert_eq!(translate_natural_language("status"), None);
        assert_eq!(translate_natural_language("quit now"), None);
        assert_eq!(translate_natural_language("/quit"), None);
    }

    #[test]
    fn test_every_binding_runs_a_known_slash_command() {
        for binding in NATURAL_LANGUAGE_BINDINGS {
            assert!(
                crate::SLASH_COMMANDS.contains(&binding.command),
                "'{}' runs unknown command '{}'",
                binding.phrase,
                binding.command
            );
        }
    }

    #[test]
    fn test_every_complete_binding_translates() {
        for binding in NATURAL_LANGUAGE_BINDINGS {
            let input = if binding.phrase.ends_with(' ') {
                format!("{}arg", binding.phrase)
            } else {
                binding.phrase.to_string()
            };
            assert!(
                translate_natural_language(&input).is_some(),
                "'{input}' does not translate"
            );
        }
    }

    #[test]
    fn test_ghost_candidates() {
        assert_eq!(natural_language_ghost_candidates("q"), vec!["uit"]);
        assert_eq!(
            natural_language_ghost_candidates("li"),
            vec!["st models", "st tools"]
        );
        assert_eq!(natural_language_ghost_candidates("HE"), vec!["lp"]);
        assert!(natural_language_ghost_candidates("quit").is_empty());
        assert!(natural_language_ghost_candidates("").is_empty());
        assert!(natural_language_ghost_candidates("/q").is_empty());
        assert!(natural_language_ghost_candidates("xyz").is_empty());
    }

    #[test]
    fn test_first_ghost_word() {
        assert_eq!(first_ghost_word("t tools"), "t ");
        assert_eq!(first_ghost_word("uit"), "uit");
        assert_eq!(first_ghost_word(" model "), " model ");
        assert_eq!(first_ghost_word("e model "), "e ");
    }

    #[test]
    fn test_natural_argument_prefix() {
        assert_eq!(
            natural_argument_prefix("use model ge"),
            Some(("/model", 10, "ge"))
        );
        assert_eq!(natural_argument_prefix("use model gemma x"), None);
        assert_eq!(natural_argument_prefix("list tools"), None);
    }
}
