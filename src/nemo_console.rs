//! TBFDesk console session for the Sciter UI: a command line on the remote computer, no
//! screen. Flutter has its own terminal page; this is the Sciter counterpart.
//!
//!   tbfdesk --terminal <id> [--password-file <f> | --password-stdin] [--relay]
//!   tbfdesk --terminal-admin <id> ...      (Windows peer: elevated shell, asks for the
//!                                           peer's administrator login)
//!
//! It runs the SAME session core as the Flutter terminal (`ConnType::TERMINAL` through
//! `ui_session_interface::Session` and `io_loop`), so login, 2FA, device key, direct/relay,
//! the outgoing-connection policy and the controlled side's "Enable terminal" permission
//! all behave as in every other session. Only the screen part differs: the computer's own
//! terminal window does the VT emulation. Keystrokes go to the remote PTY as raw bytes and
//! the remote output is written to stdout unchanged.
//!
//! The right-click entry "Terminal (command line only)" starts this in a new terminal
//! window ([`open_window`]); on Windows the process allocates its own console.

use crate::{
    client::{Data, Interface},
    ui_session_interface::{InvokeUiSession, Session},
};
use hbb_common::{
    log,
    message_proto::*,
    rendezvous_proto::ConnType,
};
use std::{
    io::{Read, Write},
    sync::{atomic::AtomicUsize, mpsc, Arc, Mutex, RwLock},
    time::Duration,
};

const TERMINAL_ID: i32 = 0;

enum Ev {
    /// A login step needs input (msgbox type, title).
    Prompt(String, String),
    /// The controlled side has more than one Windows session: (sid, name).
    WindowsSessions(Vec<(String, String)>),
    Connected,
    Opened(bool, String),
    Output(Vec<u8>),
    Closed(i32),
    Fatal(String),
    Info(String),
}

#[derive(Clone, Default)]
pub struct ConsoleHandler {
    tx: Arc<Mutex<Option<mpsc::Sender<Ev>>>>,
}

impl ConsoleHandler {
    fn emit(&self, ev: Ev) {
        if let Some(tx) = self.tx.lock().unwrap().as_ref() {
            tx.send(ev).ok();
        }
    }
}

fn tr(s: &str) -> String {
    crate::client::translate(s.to_owned())
}

impl InvokeUiSession for ConsoleHandler {
    fn set_cursor_data(&self, _cd: CursorData) {}
    fn set_cursor_id(&self, _id: String) {}
    fn set_cursor_position(&self, _cp: CursorPosition) {}
    fn set_display(&self, _x: i32, _y: i32, _w: i32, _h: i32, _ce: bool, _scale: f64) {}
    fn switch_display(&self, _display: &SwitchDisplay) {}
    fn set_peer_info(&self, _peer_info: &PeerInfo) {}
    fn set_displays(&self, _displays: &Vec<DisplayInfo>) {}
    fn set_platform_additions(&self, _data: &str) {}
    fn on_connected(&self, conn_type: ConnType) {
        if conn_type == ConnType::TERMINAL {
            self.emit(Ev::Connected);
        }
    }
    fn update_privacy_mode(&self) {}
    fn set_permission(&self, _name: &str, _value: bool) {}
    fn close_success(&self) {}
    fn update_quality_status(&self, _qs: crate::client::QualityStatus) {}
    fn set_connection_type(&self, is_secured: bool, direct: bool, _stream_type: &str) {
        self.emit(Ev::Info(format!(
            "{} {}",
            if direct { tr("Direct") } else { tr("Relay") },
            if is_secured { "(TLS/NaCl)" } else { "" }
        )));
    }
    fn set_fingerprint(&self, _fingerprint: String) {}
    fn job_error(&self, _id: i32, _err: String, _file_num: i32) {}
    fn job_done(&self, _id: i32, _file_num: i32) {}
    fn clear_all_jobs(&self) {}
    fn new_message(&self, _msg: String) {}
    fn update_transfer_list(&self) {}
    fn load_last_job(&self, _cnt: i32, _job_json: &str, _auto_start: bool) {}
    fn update_folder_files(
        &self,
        _id: i32,
        _entries: &Vec<FileEntry>,
        _path: String,
        _is_local: bool,
        _only_count: bool,
    ) {
    }
    fn confirm_delete_files(&self, _id: i32, _i: i32, _name: String) {}
    fn override_file_confirm(
        &self,
        _id: i32,
        _file_num: i32,
        _to: String,
        _is_upload: bool,
        _is_identical: bool,
    ) {
    }
    fn update_block_input_state(&self, _on: bool) {}
    fn job_progress(&self, _id: i32, _file_num: i32, _speed: f64, _finished_size: f64) {}
    fn adapt_size(&self) {}
    fn on_rgba(&self, _display: usize, _rgba: &mut scrap::ImageRgb) {}
    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str, _retry: bool) {
        match msgtype {
            "input-password" | "re-input-password" | "input-2fa" | "terminal-admin-login"
            | "terminal-admin-login-password" => {
                self.emit(Ev::Prompt(msgtype.to_owned(), title.to_owned()))
            }
            t if t.contains("error") || t.contains("nocancel") => {
                let text = if text.is_empty() {
                    tr(title)
                } else {
                    format!("{}: {}", tr(title), tr(text))
                };
                self.emit(Ev::Fatal(text))
            }
            _ => {
                if !title.is_empty() || !text.is_empty() {
                    self.emit(Ev::Info(format!("{} {}", tr(title), tr(text))));
                }
            }
        }
    }
    fn cancel_msgbox(&self, _tag: &str) {}
    fn switch_back(&self, _id: &str) {}
    fn portable_service_running(&self, _running: bool) {}
    fn on_voice_call_started(&self) {}
    fn on_voice_call_closed(&self, _reason: &str) {}
    fn on_voice_call_waiting(&self) {}
    fn on_voice_call_incoming(&self) {}
    fn get_rgba(&self, _display: usize) -> *const u8 {
        std::ptr::null()
    }
    fn next_rgba(&self, _display: usize) {}
    fn set_multiple_windows_session(&self, sessions: Vec<WindowsSession>) {
        self.emit(Ev::WindowsSessions(
            sessions
                .into_iter()
                .map(|s| (s.sid.to_string(), s.name))
                .collect(),
        ));
    }
    fn set_current_display(&self, _disp_idx: i32) {}
    fn update_record_status(&self, _start: bool) {}
    fn printer_request(&self, _id: i32, _path: String) {}
    fn handle_screenshot_resp(&self, _sid: String, _msg: String) {}
    fn handle_terminal_response(&self, response: TerminalResponse) {
        use hbb_common::message_proto::terminal_response::Union;
        match response.union {
            Some(Union::Opened(o)) => self.emit(Ev::Opened(o.success, o.message)),
            Some(Union::Data(d)) => self.emit(Ev::Output(if d.compressed {
                hbb_common::compress::decompress(&d.data)
            } else {
                d.data.to_vec()
            })),
            Some(Union::Closed(c)) => self.emit(Ev::Closed(c.exit_code)),
            Some(Union::Error(e)) => self.emit(Ev::Fatal(e.message)),
            _ => {}
        }
    }
}

// ---- the local terminal ------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod tty {
    use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg, Termios};
    use std::sync::Mutex;

    static ORIG: Mutex<Option<Termios>> = Mutex::new(None);

    pub fn prepare() -> bool {
        std::io::IsTerminal::is_terminal(&std::io::stdin())
    }

    pub fn raw() {
        if let Ok(t) = tcgetattr(std::io::stdin()) {
            let mut r = t.clone();
            cfmakeraw(&mut r);
            if tcsetattr(std::io::stdin(), SetArg::TCSANOW, &r).is_ok() {
                *ORIG.lock().unwrap() = Some(t);
            }
        }
    }

    pub fn restore() {
        if let Some(t) = ORIG.lock().unwrap().take() {
            tcsetattr(std::io::stdin(), SetArg::TCSANOW, &t).ok();
        }
    }

    /// (rows, cols)
    pub fn size() -> (u32, u32) {
        let mut ws: nix::libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { nix::libc::ioctl(1, nix::libc::TIOCGWINSZ, &mut ws) } == 0
            && ws.ws_row > 0
            && ws.ws_col > 0
        {
            (ws.ws_row as u32, ws.ws_col as u32)
        } else {
            (24, 80)
        }
    }

    pub fn set_title(t: &str) {
        print!("\x1b]0;{}\x07", t);
    }
}

#[cfg(windows)]
mod tty {
    use std::sync::Mutex;
    use winapi::um::{
        consoleapi::{AllocConsole, GetConsoleMode, SetConsoleMode},
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::INVALID_HANDLE_VALUE,
        processenv::{GetStdHandle, SetStdHandle},
        winbase::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        wincon::{
            GetConsoleScreenBufferInfo, SetConsoleCP, SetConsoleOutputCP, SetConsoleTitleW,
            CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
            ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        },
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE},
    };

    const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;
    static ORIG: Mutex<Option<(u32, u32)>> = Mutex::new(None);

    fn open(name: &str) -> HANDLE {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        }
    }

    /// The Sciter binary is a GUI program: give it a console window of its own and point
    /// the standard handles at it (UTF-8 both ways).
    pub fn prepare() -> bool {
        unsafe {
            let mut mode = 0u32;
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let has_console = !h.is_null() && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mut mode) != 0;
            if !has_console {
                AllocConsole();
                let cin = open("CONIN$");
                let cout = open("CONOUT$");
                if cin == INVALID_HANDLE_VALUE || cout == INVALID_HANDLE_VALUE {
                    return false;
                }
                SetStdHandle(STD_INPUT_HANDLE, cin);
                SetStdHandle(STD_OUTPUT_HANDLE, cout);
                SetStdHandle(STD_ERROR_HANDLE, cout);
            }
            SetConsoleCP(65001);
            SetConsoleOutputCP(65001);
            // VT output also while still prompting (colours of the remote banner etc.)
            let out = GetStdHandle(STD_OUTPUT_HANDLE);
            if GetConsoleMode(out, &mut mode) != 0 {
                SetConsoleMode(out, mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
        true
    }

    pub fn raw() {
        unsafe {
            let (hin, hout) = (GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE));
            let (mut min, mut mout) = (0u32, 0u32);
            if GetConsoleMode(hin, &mut min) == 0 || GetConsoleMode(hout, &mut mout) == 0 {
                return;
            }
            *ORIG.lock().unwrap() = Some((min, mout));
            // keys as VT sequences, no local echo / line editing, Ctrl+C as a byte
            SetConsoleMode(
                hin,
                (min & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT,
            );
            SetConsoleMode(
                hout,
                mout | ENABLE_PROCESSED_OUTPUT
                    | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                    | DISABLE_NEWLINE_AUTO_RETURN,
            );
        }
    }

    pub fn restore() {
        if let Some((min, mout)) = ORIG.lock().unwrap().take() {
            unsafe {
                SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), min);
                SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), mout);
            }
        }
    }

    /// (rows, cols) of the visible window
    pub fn size() -> (u32, u32) {
        unsafe {
            let mut i: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut i) != 0 {
                let rows = (i.srWindow.Bottom - i.srWindow.Top + 1) as u32;
                let cols = (i.srWindow.Right - i.srWindow.Left + 1) as u32;
                if rows > 0 && cols > 0 {
                    return (rows, cols);
                }
            }
        }
        (24, 80)
    }

    pub fn set_title(t: &str) {
        let w: Vec<u16> = t.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { SetConsoleTitleW(w.as_ptr()) };
    }
}

fn out(bytes: &[u8]) {
    let mut o = std::io::stdout().lock();
    // The Windows console refuses invalid UTF-8 (std splits incomplete sequences itself);
    // never drop output because of one bad byte.
    if o.write_all(bytes).is_err() {
        o.write_all(String::from_utf8_lossy(bytes).as_bytes()).ok();
    }
    o.flush().ok();
}

fn line(s: &str) {
    out(format!("{}\r\n", s).as_bytes());
}

fn read_line(prompt: &str) -> String {
    out(prompt.as_bytes());
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    s.trim_end_matches(['\r', '\n']).to_owned()
}

fn read_secret(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_default()
}

fn finish(code: i32, wait: bool) -> ! {
    tty::restore();
    if wait {
        // the window closes with the process: keep the message readable
        read_line(&format!("\r\n{} ", tr("Press Enter to close this window.")));
    }
    std::process::exit(code);
}

// ---- the session -------------------------------------------------------------------------

/// `args` = everything after `--terminal` / `--terminal-admin`. Never returns.
pub fn run(args: &[String], admin: bool) -> ! {
    if !tty::prepare() {
        log::error!("console session: no terminal to run in");
        std::process::exit(2);
    }
    let Some(id) = args.first().cloned() else {
        line("usage: --terminal <id> [--password-file <file> | --password-stdin] [--relay]");
        finish(2, true);
    };
    let (password, rest) = crate::ui_interface::peer_password_from_args(&args[1..]);
    let force_relay = rest.iter().any(|a| a == "--relay");
    tty::set_title(&format!("TBFDesk {} - {}", tr("Terminal"), id));
    line(&format!("TBFDesk {} → {} …", tr("Terminal"), id));

    let (tx, rx) = mpsc::channel::<Ev>();
    let handler = ConsoleHandler::default();
    *handler.tx.lock().unwrap() = Some(tx);
    let session: Session<ConsoleHandler> = Session {
        password,
        args: rest,
        server_keyboard_enabled: Arc::new(RwLock::new(true)),
        server_file_transfer_enabled: Arc::new(RwLock::new(true)),
        server_clipboard_enabled: Arc::new(RwLock::new(true)),
        reconnect_count: Arc::new(AtomicUsize::new(0)),
        ui_handler: handler,
        ..Default::default()
    };
    // LoginConfigHandler::initialize reads IS_TERMINAL_ADMIN (as the Flutter path does)
    if admin {
        std::env::set_var("IS_TERMINAL_ADMIN", "Y");
    }
    session
        .lc
        .write()
        .unwrap()
        .initialize(id, ConnType::TERMINAL, None, force_relay, None, None, None);
    std::env::remove_var("IS_TERMINAL_ADMIN");
    session.reconnect(false);

    let mut open = false;
    loop {
        let ev = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(ev) => ev,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => finish(1, true),
        };
        match ev {
            Ev::Info(s) => {
                if !open && !s.trim().is_empty() {
                    line(s.trim());
                }
            }
            Ev::Prompt(kind, title) => {
                if !title.is_empty() && kind != "input-password" {
                    line(&tr(&title));
                }
                match kind.as_str() {
                    "input-2fa" => {
                        let code = read_line(&format!("{}: ", tr("enter-2fa-title")));
                        session.send2fa(code, false);
                    }
                    "terminal-admin-login" | "terminal-admin-login-password" => {
                        line(&tr("terminal-admin-login-tip"));
                        let user = read_line(&format!("{}: ", tr("Username")));
                        let pass = read_secret(&format!("{}: ", tr("Password")));
                        let peer_pw = if kind == "terminal-admin-login-password" {
                            read_secret(&format!("TBFDesk {}: ", tr("Password")))
                        } else {
                            String::new()
                        };
                        session.login(user, pass, peer_pw, false);
                    }
                    _ => {
                        let pw = read_secret(&format!("{}: ", tr("Password")));
                        if pw.is_empty() {
                            finish(1, false);
                        }
                        session.login(String::new(), String::new(), pw, false);
                    }
                }
            }
            Ev::WindowsSessions(list) => {
                let sid = if list.len() == 1 {
                    list[0].0.clone()
                } else {
                    for (i, (_, name)) in list.iter().enumerate() {
                        line(&format!("  {}) {}", i + 1, name));
                    }
                    let n = read_line(&format!("{} [1-{}]: ", tr("Please select the session you want to connect to"), list.len()))
                        .trim()
                        .parse::<usize>()
                        .unwrap_or(1)
                        .clamp(1, list.len());
                    list[n - 1].0.clone()
                };
                session.send_selected_session_id(sid);
            }
            Ev::Connected => {
                if open {
                    continue;
                }
                open = true;
                tty::raw();
                let (rows, cols) = tty::size();
                session.open_terminal(TERMINAL_ID, rows, cols);
                start_input(session.clone());
                start_resize(session.clone(), (rows, cols));
            }
            Ev::Opened(ok, msg) => {
                if !ok {
                    tty::restore();
                    line(&format!("{} {}", tr("Failed"), msg));
                    session.close();
                    finish(1, true);
                }
            }
            Ev::Output(bytes) => out(&bytes),
            Ev::Closed(code) => {
                tty::restore();
                line(&format!("\r\n[{} ({})]", tr("Closed"), code));
                session.close();
                std::thread::sleep(Duration::from_millis(200));
                finish(0, false);
            }
            Ev::Fatal(msg) => {
                tty::restore();
                line(&format!("\r\n{}", msg));
                session.close();
                finish(1, true);
            }
        }
    }
}

fn send_data(session: &Session<ConsoleHandler>, data: &[u8]) {
    let mut action = TerminalAction::new();
    action.set_data(TerminalData {
        terminal_id: TERMINAL_ID,
        data: bytes::Bytes::copy_from_slice(data),
        ..Default::default()
    });
    let mut msg = Message::new();
    msg.set_terminal_action(action);
    Interface::send(session, Data::Message(msg));
}

/// Keystrokes as raw bytes (VT sequences for special keys), never re-encoded: a read can
/// end in the middle of a UTF-8 sequence, and the remote PTY puts it back together.
fn start_input(session: Session<ConsoleHandler>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    // Windows std reports a lone Ctrl+Z as end of input; it is a key here
                    #[cfg(windows)]
                    {
                        send_data(&session, &[0x1a]);
                        continue;
                    }
                    #[cfg(not(windows))]
                    break;
                }
                Ok(n) => send_data(&session, &buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::error!("console session: stdin: {e}");
                    break;
                }
            }
        }
    });
}

fn start_resize(session: Session<ConsoleHandler>, mut last: (u32, u32)) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(300));
        let now = tty::size();
        if now != last {
            last = now;
            session.resize_terminal(TERMINAL_ID, now.0, now.1);
        }
    });
}

// ---- opening the window ------------------------------------------------------------------

/// Start a console session to `id` in a terminal window of its own. Returns an error text
/// for the UI, empty on success.
pub fn open_window(id: &str, admin: bool, force_relay: bool) -> String {
    let mut args = vec![
        if admin { "--terminal-admin" } else { "--terminal" }.to_owned(),
        id.to_owned(),
    ];
    if force_relay {
        args.push("--relay".to_owned());
    }
    #[cfg(windows)]
    {
        // the child allocates its own console window (tty::prepare)
        match crate::run_me(args) {
            Ok(_) => String::new(),
            Err(e) => {
                log::error!("console session: {e}");
                format!("{}: {}", tr("Failed"), e)
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let exe = match std::env::var("APPDIR") {
            Ok(dir) if std::path::Path::new(&dir).join("AppRun").exists() => {
                std::path::Path::new(&dir).join("AppRun")
            }
            _ => match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => return format!("{}: {}", tr("Failed"), e),
            },
        };
        for (term, exec_flag) in linux_terminals() {
            let mut cmd = std::process::Command::new(&term);
            if !exec_flag.is_empty() {
                cmd.arg(exec_flag);
            }
            cmd.arg(&exe).args(&args);
            match cmd.spawn() {
                Ok(_) => {
                    log::info!("console session to {id} in {term}");
                    return String::new();
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    log::error!("console session: {term}: {e}");
                    continue;
                }
            }
        }
        tr("No terminal program found. Install one of: konsole, gnome-terminal, xfce4-terminal, xterm.")
    }
}

/// Terminal programs to try, with the flag after which the command follows. `$TERMINAL`
/// (the user's choice) first, then the distribution's default, then common ones.
#[cfg(target_os = "linux")]
fn linux_terminals() -> Vec<(String, &'static str)> {
    let mut v = Vec::new();
    if let Ok(t) = std::env::var("TERMINAL") {
        let t = t.trim().to_owned();
        if !t.is_empty() && !t.contains(char::is_whitespace) {
            v.push((t, "-e"));
        }
    }
    for (t, f) in [
        ("x-terminal-emulator", "-e"),
        ("konsole", "-e"),
        ("gnome-terminal", "--"),
        ("xfce4-terminal", "-x"),
        ("kitty", ""),
        ("alacritty", "-e"),
        ("foot", ""),
        ("xterm", "-e"),
    ] {
        v.push((t.to_owned(), f));
    }
    v
}
