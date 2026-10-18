//! "Open log folder" / "Copy recent log" for the ⋮ menu.
//!
//! The point is to make a support exchange take one paste instead of a remote session:
//! the user clicks Copy, pastes into a mail or a chat, and the operator sees what the
//! client saw. So the text has to (a) contain the log that actually explains the usual
//! problems and (b) be safe to paste anywhere.
//!
//! (a) A remote session runs in its own child process (`--connect <id>`) that logs to
//! `<log>/connect/`, not to the main log. Everything about a session -- whether the
//! direct endpoint was tried, why it failed, whether it fell back to the relay -- is in
//! that file and only there. Copying the main log alone would hand over the one file
//! that says nothing about the connection the user is asking about. So both are taken.
//!
//! (b) The client does not log secrets on purpose, but "on purpose" is not a guarantee
//! for text that is about to leave the machine, so every line goes through `redact`.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// How much of each file to keep. Enough for the last session or two; small enough to
/// paste into a chat without it being cut off.
pub const TAIL_LINES: usize = 300;
/// A single runaway line (a dumped buffer) must not crowd out everything else.
const MAX_LINE_CHARS: usize = 2000;

/// The newest `*.log` directly inside `dir`, by modification time. `None` when the
/// directory does not exist or holds no log -- a client that never opened a session has
/// no `connect/` directory, and that is not an error.
pub fn newest_log_in(dir: &Path) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|e| e.path().extension().map(|x| x == "log").unwrap_or(false))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max_by_key(|(t, _)| *t)
        .map(|(_, p)| p)
}

/// The last `n` lines of `text`, each capped to `MAX_LINE_CHARS`.
pub fn tail(text: &str, n: usize) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .map(|l| {
            if l.chars().count() > MAX_LINE_CHARS {
                let cut: String = l.chars().take(MAX_LINE_CHARS).collect();
                format!("{cut} …[line truncated]")
            } else {
                (*l).to_owned()
            }
        })
        .collect()
}

/// Blank out anything that looks like a credential: the value after `access_token`,
/// `password`, `token`, `secret` or a device-key option, in `key=value`, `key: value`,
/// and JSON `"key":"value"` form. Over-redacting a harmless value costs nothing; leaking
/// a session token or a device key into a support chat costs a re-provisioning.
pub fn redact(line: &str) -> String {
    lazy_static::lazy_static! {
        static ref SECRET: hbb_common::regex::Regex = hbb_common::regex::Regex::new(
            r#"(?i)((?:access_?token|password|passwd|secret|nemo-device-key|device_key|\btoken)["']?\s*[:=]\s*["']?)([^\s"',}\]]+)"#
        ).unwrap();
    }
    SECRET.replace_all(line, "${1}<redacted>").into_owned()
}

/// How much of the START of the session log to keep. The connection decision -- direct
/// endpoint tried or not, why it failed, relay or hole punch -- is written in the first
/// lines of a session; a long session pushes it far past any tail. Found in the lab: a
/// tail-only copy of a real session contained no "TBFDesk direct" line at all.
pub const SESSION_HEAD_LINES: usize = 150;

/// The first `head` and last `tail` lines, with a marker for what was left out between
/// them. Short texts come back whole.
pub fn head_and_tail(text: &str, head: usize, tail_n: usize) -> Vec<String> {
    let all: Vec<&str> = text.lines().collect();
    if all.len() <= head + tail_n {
        return tail(text, all.len());
    }
    let mut out = tail(&all[..head].join("\n"), head);
    out.push(format!(
        "…[{} lines omitted]…",
        all.len() - head - tail_n
    ));
    out.extend(tail(&all[all.len() - tail_n..].join("\n"), tail_n));
    out
}

/// Build the text "Copy recent log" puts on the clipboard: a short header that says
/// which client this is, then the tail of the newest main log and of the newest session
/// log, each under a line naming the file. Returns the text and the files it read.
pub fn collect(log_root: &Path, header: &[String]) -> (String, Vec<PathBuf>) {
    let mut out: Vec<String> = header.to_vec();
    let mut read = Vec::new();
    // (label, directory, keep the start of the file too)
    let sources = [
        ("main window", log_root.to_path_buf(), false),
        ("sessions (direct / relay decisions)", log_root.join("connect"), true),
    ];
    for (what, dir, with_head) in sources {
        out.push(String::new());
        match newest_log_in(&dir) {
            Some(file) => match fs::read(&file) {
                Ok(bytes) => {
                    // Logs are UTF-8 in practice; a stray invalid byte must not cost the
                    // whole file.
                    let text = String::from_utf8_lossy(&bytes);
                    let lines = if with_head {
                        head_and_tail(&text, SESSION_HEAD_LINES, TAIL_LINES)
                    } else {
                        tail(&text, TAIL_LINES)
                    };
                    out.push(format!(
                        "===== {what}: {} ({}) =====",
                        file.display(),
                        if with_head {
                            format!("first {SESSION_HEAD_LINES} and last {TAIL_LINES} lines")
                        } else {
                            format!("last {} lines", lines.len())
                        }
                    ));
                    out.extend(lines.iter().map(|l| redact(l)));
                    read.push(file);
                }
                Err(err) => out.push(format!("===== {what}: {} unreadable: {err} =====", file.display())),
            },
            None => out.push(format!("===== {what}: no log in {} =====", dir.display())),
        }
    }
    (out.join("\n"), read)
}

/// Open `dir` in the platform's file manager. Not `open_url`: on Linux that prefers
/// Firefox, which shows a folder as a bare file:// listing instead of opening it.
pub fn open_folder(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir).ok();
    #[cfg(windows)]
    let opener = "explorer";
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(any(windows, target_os = "macos")))]
    let opener = "xdg-open";
    std::process::Command::new(opener).arg(dir).spawn().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_never_reach_the_clipboard() {
        for (input, leaked) in [
            (r#"login reply {"access_token":"eyJhbGciOi.abc.def","user":"marek"}"#, "eyJhbGciOi"),
            ("set option nemo-device-key = 'nmc5XCxb1N+Ut0N3'", "nmc5XCxb1N"),
            ("password=hunter2 for marek", "hunter2"),
            ("Authorization header token: 0123456789abcdef", "0123456789abcdef"),
        ] {
            let out = redact(input);
            assert!(!out.contains(leaked), "leaked {leaked:?} in {out:?}");
            assert!(out.contains("<redacted>"), "{out:?}");
        }
    }

    #[test]
    fn ordinary_lines_are_left_alone() {
        let line = "TBFDesk direct: established with 10.89.0.3:21218 in 585µs, no relay";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn only_the_tail_is_kept_and_runaway_lines_are_cut() {
        let text: String = (0..1000).map(|i| format!("line {i}\n")).collect();
        let t = tail(&text, 3);
        assert_eq!(t, vec!["line 997", "line 998", "line 999"]);
        let long = "x".repeat(MAX_LINE_CHARS + 50);
        assert!(tail(&long, 1)[0].ends_with("[line truncated]"));
    }

    #[test]
    fn the_session_log_is_included_because_that_is_where_connections_are_logged() {
        let root = std::env::temp_dir().join("tbfdesk-nemo-logs-test");
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(root.join("connect")).unwrap();
        fs::write(root.join("tbfdesk_rCURRENT.log"), "main line\n").unwrap();
        fs::write(
            root.join("connect").join("tbfdesk_rCURRENT.log"),
            "TBFDesk direct: TCP 85.126.226.2:21666 failed: timed out\n",
        )
        .unwrap();
        fs::write(root.join("connect").join("not-a-log.txt"), "ignored").unwrap();

        let (text, read) = collect(&root, &["TBFDesk test".to_owned()]);
        assert_eq!(read.len(), 2);
        assert!(text.starts_with("TBFDesk test"));
        assert!(text.contains("main line"));
        assert!(text.contains("85.126.226.2:21666 failed"));
        assert!(!text.contains("ignored"));
    }

    #[test]
    fn a_long_session_keeps_its_connection_decision_from_the_start() {
        let mut text = String::from("TBFDesk direct: trying 85.126.226.2:21666 for 352069946\n");
        for i in 0..2000 {
            text.push_str(&format!("frame {i}\n"));
        }
        text.push_str("Connection closed: Reset by the peer\n");
        let kept = head_and_tail(&text, SESSION_HEAD_LINES, TAIL_LINES);
        assert!(kept[0].contains("TBFDesk direct: trying"), "the decision must survive");
        assert!(kept.last().unwrap().contains("Connection closed"), "and so must the end");
        assert!(kept.iter().any(|l| l.contains("lines omitted")));
        assert_eq!(kept.len(), SESSION_HEAD_LINES + 1 + TAIL_LINES);
        // Short logs are kept whole, with no marker.
        let short = head_and_tail("a\nb\nc\n", SESSION_HEAD_LINES, TAIL_LINES);
        assert_eq!(short, vec!["a", "b", "c"]);
    }

    #[test]
    fn a_client_that_never_opened_a_session_says_so_instead_of_failing() {
        let root = std::env::temp_dir().join("tbfdesk-nemo-logs-test-nosession");
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("tbfdesk_rCURRENT.log"), "main\n").unwrap();
        let (text, read) = collect(&root, &[]);
        assert_eq!(read.len(), 1);
        assert!(text.contains("no log in"));
    }
}
