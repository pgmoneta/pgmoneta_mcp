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

//! The status line shown while the client waits for the model or a tool,
//! `⠋ Thinking 4s`, so a slow answer and a hung one are easy to tell apart.

use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::io::{self, IsTerminal, Write};
use std::time::Duration;
use tokio::time::{Instant, MissedTickBehavior};

/// While the model picks a tool or answers directly.
pub const THINKING: &str = "Thinking";
/// While the model turns a tool result into the reply.
pub const WRITING: &str = "Writing the reply";

const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const FRAME_INTERVAL: Duration = Duration::from_millis(100);
/// Nothing is drawn before this, so a quick answer doesn't flash a line.
const FIRST_DRAW: Duration = Duration::from_millis(200);
/// Back to the start of the line and erase it.
const CLEAR_LINE: &str = "\r\x1b[2K";

/// The label while a tool runs: `Running delete on primary`.
pub fn running(name: &str, args: &HashMap<String, Value>) -> String {
    match args.get("server").and_then(Value::as_str) {
        Some(server) => format!("Running {name} on {server}"),
        None => format!("Running {name}"),
    }
}

/// Awaits `future` with `label` and a timer on a line of its own, when stdout
/// is a terminal. The line is gone again when the future finishes, so whatever
/// is printed next starts on a clean line.
pub async fn wait<F: Future>(label: &str, future: F) -> F::Output {
    if io::stdout().is_terminal() {
        wait_on(&mut io::stdout(), label, future).await
    } else {
        future.await
    }
}

async fn wait_on<W: Write, F: Future>(out: &mut W, label: &str, future: F) -> F::Output {
    let started = Instant::now();
    let mut ticks = tokio::time::interval_at(started + FIRST_DRAW, FRAME_INTERVAL);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut frame = 0;
    let mut drawn = false;

    tokio::pin!(future);
    let output = loop {
        tokio::select! {
            biased;
            output = &mut future => break output,
            _ = ticks.tick() => {
                let _ = write!(out, "{CLEAR_LINE}{}", line(frame, label, started.elapsed()));
                let _ = out.flush();
                frame += 1;
                drawn = true;
            }
        }
    };

    if drawn {
        let _ = write!(out, "{CLEAR_LINE}");
        let _ = out.flush();
    }
    output
}

fn line(frame: usize, label: &str, elapsed: Duration) -> String {
    format!(
        "{} {label} {}s",
        FRAMES[frame % FRAMES.len()],
        elapsed.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_line_has_a_spinner_the_label_and_whole_seconds() {
        assert_eq!(
            line(0, THINKING, Duration::from_millis(4_900)),
            "⠋ Thinking 4s"
        );
        assert_eq!(
            line(11, "Running delete on primary", Duration::from_secs(12)),
            "⠙ Running delete on primary 12s"
        );
    }

    #[test]
    fn a_tool_is_named_with_its_server_when_there_is_one() {
        let args = HashMap::from([
            ("server".to_string(), json!("primary")),
            ("backup_id".to_string(), json!("oldest")),
        ]);
        assert_eq!(running("delete", &args), "Running delete on primary");
        assert_eq!(
            running("list_servers", &HashMap::new()),
            "Running list_servers"
        );
    }

    #[tokio::test]
    async fn a_quick_answer_draws_nothing() {
        let mut out = Vec::new();
        let answer = wait_on(&mut out, THINKING, async { 42 }).await;
        assert_eq!(answer, 42);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn a_slow_answer_shows_the_line_and_clears_it_at_the_end() {
        let mut out = Vec::new();
        let answer = wait_on(&mut out, THINKING, async {
            tokio::time::sleep(Duration::from_millis(450)).await;
            "done"
        })
        .await;
        assert_eq!(answer, "done");

        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("\r\x1b[2K⠋ Thinking 0s"), "{out:?}");
        assert!(out.contains("\r\x1b[2K⠙ Thinking 0s"), "{out:?}");
        assert!(out.ends_with("s\r\x1b[2K"), "{out:?}");
    }
}
