use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{atomic::AtomicUsize, Arc, Mutex, RwLock},
};

use sciter::{
    dom::{
        event::{EventReason, BEHAVIOR_EVENTS, EVENT_GROUPS, PHASE_MASK},
        Element, HELEMENT,
    },
    make_args,
    video::{video_destination, AssetPtr, COLOR_SPACE},
    Value,
};

use hbb_common::{
    allow_err, fs::TransferJobMeta, log, message_proto::*, rendezvous_proto::ConnType,
};

use crate::{
    client::*,
    ui_session_interface::{InvokeUiSession, Session},
};

type Video = AssetPtr<video_destination>;

/// Holds the Sciter <video> render surfaces.
///
/// Default (legacy) behavior: a SINGLE surface (`single`) is bound by the one
/// `<video #handler>` element and every decoded frame is blitted into it. This
/// is byte-for-byte the original behavior whenever `view_all == false`.
///
/// New "view all displays" behavior: when `view_all == true`, one surface per
/// remote display is bound (each `<video display="N">` tile) and frames are
/// routed to `tiles[N]` by their display index. `tile_dims` tracks the size each
/// tile surface was last (re)started with so we only re-init streaming on change.
#[derive(Default)]
struct VideoSurfaces {
    single: Option<Video>,
    tiles: HashMap<usize, Video>,
    tile_dims: HashMap<usize, (i32, i32)>,
    /// Who bound each tile: 0 = a tile in the main window, otherwise the id of the
    /// display window. A window that goes away removes a tile only if it is still the
    /// one it bound -- see DisplayWindowBehavior::detached.
    tile_owner: HashMap<usize, u64>,
    view_all: bool,
}

lazy_static::lazy_static! {
    static ref VIDEO: Arc<Mutex<VideoSurfaces>> = Default::default();
}

// ============================================================================
// "One window per remote display" (header button #mode-windows).
//
// Each extra remote display gets its own OS window, placed on its own local monitor,
// in THIS process and over THIS connection. That is what makes it cheap and quiet: no
// second connection, so no second login, no second approval prompt on the remote side,
// and no second set of video encoders there. It works because frame routing is
// already per display and process-global (VIDEO.tiles, keyed by display index): a
// <video> element in another window that binds itself under display N receives display
// N's frames exactly like a tile in the main window does.
//
// Windows are created on the UI thread (script calls run there) and are owned by the
// main window, so they never outlive the session and never quit the app on close
// (no SW_MAIN).
// ============================================================================
thread_local! {
    /// display index -> (window id, window). The id tells a window that is still current
    /// from one that has been replaced or closed on purpose.
    static DISPLAY_WINDOWS: std::cell::RefCell<HashMap<usize, (u64, sciter::Window)>> =
        Default::default();
}

static NEXT_DISPLAY_WINDOW_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

thread_local! {
    /// The session window's handle, recorded on the UI thread when the session element
    /// attaches, so a display window can name its owner WITHOUT taking
    /// `SciterHandler::element`. That mutex is held by other threads for the whole of a
    /// script call, which Sciter runs on the UI thread and waits for; the UI thread
    /// blocking on it from open_display_window deadlocked both until a timeout -- a
    /// 20 s freeze, frames included, seen intermittently in the Windows VM.
    static SESSION_HWND: std::cell::Cell<Option<sciter::types::HWINDOW>> =
        std::cell::Cell::new(None);
    /// The session's own `<video #handler>`, for the same reason: a display window the
    /// user closed tells the script through it, not through `SciterHandler::call`.
    static SESSION_ELEMENT: std::cell::RefCell<Option<Element>> = Default::default();
}

/// The behavior on the single <video> of a display window. It binds the surface into
/// VIDEO.tiles under its display index and forwards input to the real session.
struct DisplayWindowBehavior {
    session: Session<SciterHandler>,
    display: usize,
    id: u64,
}

impl DisplayWindowBehavior {
    fn send_mouse(
        &mut self,
        mask: i32,
        x: i32,
        y: i32,
        alt: bool,
        ctrl: bool,
        shift: bool,
        command: bool,
    ) {
        self.session.send_mouse(mask, x, y, alt, ctrl, shift, command);
    }

    fn enter(&mut self, keyboard_mode: String) {
        self.session.enter(keyboard_mode);
    }

    fn leave(&mut self, keyboard_mode: String) {
        self.session.leave(keyboard_mode);
    }

    fn get_keyboard_mode(&mut self) -> String {
        self.session.get_keyboard_mode()
    }
}

impl sciter::EventHandler for DisplayWindowBehavior {
    fn get_subscription(&mut self) -> Option<EVENT_GROUPS> {
        Some(EVENT_GROUPS::HANDLE_BEHAVIOR_EVENT)
    }

    // On Windows a window closes ASYNCHRONOUSLY: dismiss() posts the close and this
    // runs later -- after a mode change has already opened the replacement window for
    // the same display. Keyed by display index alone, the late call removed the NEW
    // window's surface (black window) and reported a user close, which threw the
    // session out of the mode (found in the Windows VM when changing the display
    // selection in window-per-display mode). So everything here is checked against
    // this window's id: it only undoes what is still its own.
    fn detached(&mut self, _root: HELEMENT) {
        {
            let mut lock = VIDEO.lock().unwrap();
            if lock.tile_owner.get(&self.display) == Some(&self.id) {
                lock.tiles.remove(&self.display);
                lock.tile_dims.remove(&self.display);
                lock.tile_owner.remove(&self.display);
            }
        }
        let closed_by_user = DISPLAY_WINDOWS.with(|w| {
            let mut w = w.borrow_mut();
            if matches!(w.get(&self.display), Some((id, _)) if *id == self.id) {
                w.remove(&self.display);
                true
            } else {
                false
            }
        });
        log::info!(
            "display window {} closed{}",
            self.display,
            if closed_by_user { " by the user" } else { "" }
        );
        // Only a window the user closed means anything to the main window: the session
        // then falls back to showing that display there. Windows closed by a mode change
        // were taken out of DISPLAY_WINDOWS before they were dismissed.
        if closed_by_user {
            let display = self.display as i32;
            SESSION_ELEMENT.with(|e| {
                if let Some(e) = e.borrow().as_ref() {
                    allow_err!(e.call_method("onDisplayWindowClosed", &make_args!(display)));
                }
            });
        }
    }

    fn on_event(
        &mut self,
        _root: HELEMENT,
        _source: HELEMENT,
        _target: HELEMENT,
        code: BEHAVIOR_EVENTS,
        phase: PHASE_MASK,
        reason: EventReason,
    ) -> bool {
        if phase != PHASE_MASK::BUBBLING {
            return false;
        }
        match code {
            BEHAVIOR_EVENTS::VIDEO_BIND_RQ => {
                if let EventReason::VideoBind(ptr) = reason {
                    log::info!(
                        "display window {}: video bind ({})",
                        self.display,
                        if ptr.is_null() { "unbind" } else { "surface" }
                    );
                    if !ptr.is_null() {
                        let site = AssetPtr::adopt(ptr as *mut video_destination);
                        {
                            let mut lock = VIDEO.lock().unwrap();
                            lock.tile_dims.remove(&self.display);
                            lock.tiles.insert(self.display, site);
                            lock.tile_owner.insert(self.display, self.id);
                        }
                        // Ask for a fresh frame of this display. The peer only sends a
                        // frame when its screen changes, and the one requested when the
                        // mode started can arrive before this window exists -- it is
                        // then lost, and a static remote screen leaves the window black
                        // for good. Found on Windows: the window bound ~30 ms after the
                        // display's first frame, and stayed black.
                        self.session.refresh_video(self.display as i32);
                    }
                }
                true
            }
            BEHAVIOR_EVENTS::VIDEO_STARTED | BEHAVIOR_EVENTS::VIDEO_STOPPED => {
                log::info!("display window {}: {:?}", self.display, code);
                true
            }
            _ => false,
        }
    }

    sciter::dispatch_script_call! {
        fn send_mouse(i32, i32, i32, bool, bool, bool, bool);
        fn enter(String);
        fn leave(String);
        fn get_keyboard_mode();
    }
}

/// Close every display window. The windows are taken out of the map FIRST and closed
/// afterwards: closing one runs its behavior's `detached`, which removes itself from
/// the same map, and doing that while this function still held the borrow would be a
/// RefCell double borrow -- a panic in the UI thread, i.e. the session window dying.
fn close_all_display_windows() {
    let windows: Vec<sciter::Window> =
        DISPLAY_WINDOWS.with(|w| w.borrow_mut().drain().map(|(_, (_, win))| win).collect());
    for win in windows {
        win.dismiss();
    }
}

/// "x,y,w,h" -> (x, y, w, h). Rects travel as strings to keep the script call's arity
/// small; anything malformed or empty is refused rather than guessed.
fn parse_rect(s: &str) -> Option<(i32, i32, i32, i32)> {
    let v: Vec<i32> = s
        .split(',')
        .map(|p| p.trim().parse::<f64>().map(|f| f.round() as i32))
        .collect::<Result<_, _>>()
        .ok()?;
    match v[..] {
        [x, y, w, h] if w > 0 && h > 0 => Some((x, y, w, h)),
        _ => None,
    }
}

/// The page a display window loads. `remote` is the remote display's rect in the peer's
/// virtual desktop, so mouse positions inside the window map back to remote
/// coordinates the same way the main window's tiles do it (remote.tis handleTileMouse).
fn display_window_html(remote: (i32, i32, i32, i32), monitor_label: &str) -> String {
    let (rx, ry, rw, rh) = remote;
    format!(
        r#"<html window-resizable window-frame="default">
<head>
<style>
html {{ background: #111; }}
body {{ margin: 0; padding: 0; size: *; overflow: hidden; }}
video#handler {{ behavior: native-display video; size: *; foreground-size: contain; }}
div#hint {{ position: absolute; left: 12px; top: 10px; color: #bbb; font: system;
           background: rgba(0,0,0,0.55); padding: 4px 10px; border-radius: 4px; }}
</style>
<script type="text/tiscript">
const R = {{ x: {rx}, y: {ry}, w: {rw}, h: {rh} }};
var handler = $(#handler);
var entered = false;
// Map an element-relative position (device px) to the remote desktop. The frame is
// drawn with foreground-size: contain, so it is centred and letterboxed in the window.
function toRemote(ex, ey) {{
    var w = handler.box(#width, #inner);
    var h = handler.box(#height, #inner);
    // toFloat(): int / int is integer division in TIScript (fit would be 0).
    var fit = w.toFloat() / R.w;
    if (h.toFloat() / R.h < fit) fit = h.toFloat() / R.h;
    var ox = (w - R.w * fit) / 2;
    var oy = (h - R.h * fit) / 2;
    var x = ((ex - ox) / fit).toInteger();
    var y = ((ey - oy) / fit).toInteger();
    if (x < 0) x = 0; if (x >= R.w) x = R.w - 1;
    if (y < 0) y = 0; if (y >= R.h) y = R.h - 1;
    return [R.x + x, R.y + y];
}}
// Re-assert the keyboard grab after entering and while the pointer moves. The session's
// main window and this one share ONE grab, and the other window's late "leave" can
// release it after this window's "enter" (remote.tis holdKeyboardGrab explains it).
var grab_pending = false;
function holdGrab() {{
    if (grab_pending) return;
    grab_pending = true;
    self.timer(250ms, function() {{
        grab_pending = false;
        if (entered) handler.enter(handler.get_keyboard_mode());
    }});
}}
handler.onMouse = function(evt) {{
    var mask = 0, dx = 0, dy = 0;
    switch (evt.type) {{
      case Event.MOUSE_DOWN: mask = 1; break;
      case Event.MOUSE_UP: mask = 2; break;
      case Event.MOUSE_MOVE: mask = 0; break;
      case Event.MOUSE_DCLICK: mask = 1; break;
      case Event.MOUSE_WHEEL:
        mask = 3;
        {{
            var (rdx, rdy) = evt.wheelDeltas;
            dx = rdx > 0 ? 1 : (rdx < 0 ? -1 : 0);
            dy = rdy > 0 ? 1 : (rdy < 0 ? -1 : 0);
            if (Math.abs(rdx) > Math.abs(rdy)) dy = 0; else dx = 0;
        }}
        if (dx == 0 && dy == 0) return true;
        break;
      case Event.MOUSE_ENTER:
        entered = true; handler.enter(handler.get_keyboard_mode()); holdGrab(); return true;
      case Event.MOUSE_LEAVE:
        entered = false; handler.leave(handler.get_keyboard_mode()); return true;
      default: return false;
    }}
    if (mask == 0 && entered) holdGrab();
    var x = dx, y = dy;
    if (mask != 3) {{ var p = toRemote(evt.x, evt.y); x = p[0]; y = p[1]; }}
    handler.send_mouse((evt.buttons << 3) | mask, x, y,
        evt.altKey, evt.ctrlKey, evt.shiftKey, evt.commandKey);
    return true;
}};
// Fill the monitor this window was placed on. The hint says which remote display this
// is, and fades once the first frame has had time to arrive.
function self.ready() {{
    view.windowState = View.WINDOW_FULL_SCREEN;
    self.timer(150ms, function() {{ view.windowState = View.WINDOW_FULL_SCREEN; }});
    self.timer(4s, function() {{ var h = $(#hint); if (h) h.style.set {{ display: "none" }}; }});
}}
</script>
</head>
<body><video #handler /><div #hint>{monitor_label}</div></body>
</html>"#
    )
}

/// SciterHandler
/// * element
/// * close_state  for file path when close
#[derive(Clone, Default)]
pub struct SciterHandler {
    element: Arc<Mutex<Option<Element>>>,
    close_state: HashMap<String, String>,
}

impl SciterHandler {
    #[inline]
    fn call(&self, func: &str, args: &[Value]) {
        if let Some(ref e) = self.element.lock().unwrap().as_ref() {
            allow_err!(e.call_method(func, args));
        }
    }

    #[inline]
    fn call2(&self, func: &str, args: &[Value]) {
        if let Some(ref e) = self.element.lock().unwrap().as_ref() {
            allow_err!(e.call_method(func, &super::value_crash_workaround(args)[..]));
        }
    }

    fn make_displays_array(displays: &Vec<DisplayInfo>) -> Value {
        let mut displays_value = Value::array(0);
        for d in displays.iter() {
            let mut display = Value::map();
            display.set_item("x", d.x);
            display.set_item("y", d.y);
            display.set_item("width", d.width);
            display.set_item("height", d.height);
            display.set_item("cursor_embedded", d.cursor_embedded);
            display.set_item("scale", if d.scale <= 0.0 { 1.0 } else { d.scale });
            displays_value.push(display);
        }
        displays_value
    }

    fn make_platform_additions(data: &str) -> Option<Value> {
        if let Ok(v2) = serde_json::from_str::<HashMap<String, serde_json::Value>>(data) {
            let mut value = Value::map();
            for (k, v) in v2 {
                match v {
                    serde_json::Value::String(s) => {
                        value.set_item(k, s);
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(n) = n.as_i64() {
                            value.set_item(k, n as i32);
                        } else if let Some(n) = n.as_f64() {
                            value.set_item(k, n);
                        }
                    }
                    serde_json::Value::Bool(b) => {
                        value.set_item(k, b);
                    }
                    serde_json::Value::Array(arr) if k == "supported_privacy_mode_impl" => {
                        let mut impls = Value::array(0);
                        for item in arr {
                            if let serde_json::Value::Array(entry) = item {
                                let impl_key = entry.get(0).and_then(|v| v.as_str());
                                let impl_name = entry.get(1).and_then(|v| v.as_str());
                                if let (Some(impl_key), Some(impl_name)) = (impl_key, impl_name) {
                                    let mut impl_item = Value::array(0);
                                    impl_item.push(impl_key);
                                    impl_item.push(impl_name);
                                    impls.push(impl_item);
                                }
                            }
                        }
                        value.set_item(k, impls);
                    }
                    _ => {
                        // ignore for now
                    }
                }
            }
            if value.len() > 0 {
                return Some(value);
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl InvokeUiSession for SciterHandler {
    fn set_cursor_data(&self, cd: CursorData) {
        let mut colors = hbb_common::compress::decompress(&cd.colors);
        if colors.iter().filter(|x| **x != 0).next().is_none() {
            log::info!("Fix transparent");
            // somehow all 0 images shows black rect, here is a workaround
            colors[3] = 1;
        }
        let mut png = Vec::new();
        if let Ok(()) = repng::encode(&mut png, cd.width as _, cd.height as _, &colors) {
            self.call(
                "setCursorData",
                &make_args!(
                    cd.id.to_string(),
                    cd.hotx,
                    cd.hoty,
                    cd.width,
                    cd.height,
                    &png[..]
                ),
            );
        }
    }

    fn set_display(&self, x: i32, y: i32, w: i32, h: i32, cursor_embedded: bool, scale: f64) {
        let scale = if scale <= 0.0 { 1.0 } else { scale };
        self.call("setDisplay", &make_args!(x, y, w, h, cursor_embedded, scale));
        // https://sciter.com/forums/topic/color_spaceiyuv-crash
        // Nothing spectacular in decoder – done on CPU side.
        // So if you can do BGRA translation on your side – the better.
        // BGRA is used as internal image format so it will not require additional transformations.
        // Only (re)initializes the legacy single surface. Tile surfaces used by
        // "view all" mode are (re)started lazily in `on_rgba` from the actual
        // frame dimensions, so this path is unchanged for default behavior.
        VIDEO.lock().unwrap().single.as_mut().map(|v| {
            v.stop_streaming().ok();
            let ok = v.start_streaming((w, h), COLOR_SPACE::Rgb32, None);
            log::info!("[video] reinitialized: {:?}", ok);
        });
    }

    fn update_privacy_mode(&self) {
        self.call("updatePrivacyMode", &[]);
    }

    fn set_permission(&self, name: &str, value: bool) {
        self.call2("setPermission", &make_args!(name, value));
    }

    fn close_success(&self) {
        self.call2("closeSuccess", &make_args!());
    }

    fn update_quality_status(&self, status: QualityStatus) {
        self.call2(
            "updateQualityStatus",
            &make_args!(
                status.speed.map_or(Value::null(), |it| it.into()),
                status
                    .fps
                    .iter()
                    .next()
                    .map_or(Value::null(), |(_, v)| (*v).into()),
                status.delay.map_or(Value::null(), |it| it.into()),
                status.target_bitrate.map_or(Value::null(), |it| it.into()),
                status
                    .codec_format
                    .map_or(Value::null(), |it| it.to_string().into()),
                status.chroma.map_or(Value::null(), |it| it.into())
            ),
        );
    }

    fn set_cursor_id(&self, id: String) {
        self.call("setCursorId", &make_args!(id));
    }

    fn set_cursor_position(&self, cp: CursorPosition) {
        self.call("setCursorPosition", &make_args!(cp.x, cp.y));
    }

    fn set_connection_type(&self, is_secured: bool, direct: bool, stream_type: &str) {
        self.call(
            "setConnectionType",
            &make_args!(is_secured, direct, stream_type.to_string()),
        );
    }

    fn set_fingerprint(&self, _fingerprint: String) {}

    fn job_error(&self, id: i32, err: String, file_num: i32) {
        self.call("jobError", &make_args!(id, err, file_num));
    }

    fn job_done(&self, id: i32, file_num: i32) {
        self.call("jobDone", &make_args!(id, file_num));
    }

    fn clear_all_jobs(&self) {
        self.call("clearAllJobs", &make_args!());
    }

    fn load_last_job(&self, cnt: i32, job_json: &str, auto_start: bool) {
        let job: Result<TransferJobMeta, serde_json::Error> = serde_json::from_str(job_json);
        if let Ok(job) = job {
            let path;
            let to;
            if job.is_remote {
                path = job.remote.clone();
                to = job.to.clone();
            } else {
                path = job.to.clone();
                to = job.remote.clone();
            }
            self.call(
                "addJob",
                &make_args!(
                    cnt,
                    path,
                    to,
                    job.file_num,
                    job.show_hidden,
                    job.is_remote,
                    auto_start
                ),
            );
        }
    }

    fn update_folder_files(
        &self,
        id: i32,
        entries: &Vec<FileEntry>,
        path: String,
        _is_local: bool,
        only_count: bool,
    ) {
        let mut m = make_fd(id, entries, only_count);
        m.set_item("path", path);
        self.call("updateFolderFiles", &make_args!(m));
    }

    fn update_transfer_list(&self) {
        self.call("updateTransferList", &make_args!());
    }

    fn confirm_delete_files(&self, id: i32, i: i32, name: String) {
        self.call("confirmDeleteFiles", &make_args!(id, i, name));
    }

    fn override_file_confirm(
        &self,
        id: i32,
        file_num: i32,
        to: String,
        is_upload: bool,
        is_identical: bool,
    ) {
        self.call(
            "overrideFileConfirm",
            &make_args!(id, file_num, to, is_upload, is_identical),
        );
    }

    fn job_progress(&self, id: i32, file_num: i32, speed: f64, finished_size: f64) {
        self.call(
            "jobProgress",
            &make_args!(id, file_num, speed, finished_size),
        );
    }

    fn adapt_size(&self) {
        self.call("adaptSize", &make_args!());
    }

    fn on_rgba(&self, display: usize, rgba: &mut scrap::ImageRgb) {
        let mut lock = VIDEO.lock().unwrap();
        // "View all displays" mode: route each display's frame to its own tile
        // surface. Streaming is (re)started lazily using the actual frame size.
        if lock.view_all && lock.tiles.contains_key(&display) {
            let dims = (rgba.w as i32, rgba.h as i32);
            let need_restart = lock.tile_dims.get(&display) != Some(&dims);
            if need_restart {
                lock.tile_dims.insert(display, dims);
            }
            if let Some(v) = lock.tiles.get_mut(&display) {
                if need_restart {
                    v.stop_streaming().ok();
                    let started = v.start_streaming(dims, COLOR_SPACE::Rgb32, None);
                    // Once per (re)start, so a surface that never paints says why.
                    log::info!("[video] tile {display} started at {dims:?}: {started:?}");
                }
                if let Err(e) = v.render_frame(&rgba.raw) {
                    if need_restart {
                        log::warn!("[video] tile {display} render failed: {e:?}");
                    }
                }
            }
            return;
        }
        if lock.view_all && !lock.tile_dims.contains_key(&display) {
            // A display is streaming but nothing is bound to draw it (its tile or
            // display window never sent VIDEO_BIND_RQ). Said once: the marker is cleared
            // when a surface binds, which also forces that surface's first restart.
            lock.tile_dims.insert(display, (rgba.w as i32, rgba.h as i32));
            log::warn!("[video] display {display} is streaming but has no surface bound");
        }
        // Default (legacy) behavior: blit into the single surface.
        lock.single
            .as_mut()
            .map(|v| v.render_frame(&rgba.raw).ok());
    }

    fn set_peer_info(&self, pi: &PeerInfo) {
        let mut pi_sciter = Value::map();
        pi_sciter.set_item("username", pi.username.clone());
        pi_sciter.set_item("hostname", pi.hostname.clone());
        pi_sciter.set_item("platform", pi.platform.clone());
        pi_sciter.set_item("sas_enabled", pi.sas_enabled);
        pi_sciter.set_item("displays", Self::make_displays_array(&pi.displays));
        pi_sciter.set_item("current_display", pi.current_display);
        pi_sciter.set_item("version", pi.version.clone());
        if let Some(v) = Self::make_platform_additions(&pi.platform_additions) {
            pi_sciter.set_item("platform_additions", v);
        }
        self.call("updatePi", &make_args!(pi_sciter));
    }

    fn set_displays(&self, displays: &Vec<DisplayInfo>) {
        self.call(
            "updateDisplays",
            &make_args!(Self::make_displays_array(displays)),
        );
    }

    fn set_platform_additions(&self, _data: &str) {
        // Ignore for sciter version.
    }

    fn set_current_display(&self, _disp_idx: i32) {
        self.call("setCurrentDisplay", &make_args!(_disp_idx));
    }

    fn set_multiple_windows_session(&self, sessions: Vec<WindowsSession>) {
        let mut v = Value::array(0);
        let mut sessions = sessions;
        for s in sessions.drain(..) {
            let mut obj = Value::map();
            obj.set_item("sid", s.sid.to_string());
            obj.set_item("name", s.name);
            v.push(obj);
        }
        self.call("setMultipleWindowsSession", &make_args!(v));
    }

    fn on_connected(&self, conn_type: ConnType) {
        match conn_type {
            ConnType::DEFAULT_CONN => {
                crate::keyboard::client::start_grab_loop();
            }
            _ => {}
        }
    }

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, link: &str, retry: bool) {
        self.call2(
            "msgbox_retry",
            &make_args!(msgtype, title, text, link, retry),
        );
    }

    fn cancel_msgbox(&self, tag: &str) {
        self.call("cancel_msgbox", &make_args!(tag));
    }

    fn new_message(&self, msg: String) {
        self.call("newMessage", &make_args!(msg));
    }

    fn switch_display(&self, display: &SwitchDisplay) {
        self.call("switchDisplay", &make_args!(display.display));
    }

    fn update_block_input_state(&self, on: bool) {
        self.call("updateBlockInputState", &make_args!(on));
    }

    fn switch_back(&self, _id: &str) {}

    fn portable_service_running(&self, _running: bool) {}

    fn on_voice_call_started(&self) {
        self.call("onVoiceCallStart", &make_args!());
    }

    fn on_voice_call_closed(&self, reason: &str) {
        self.call("onVoiceCallClosed", &make_args!(reason));
    }

    fn on_voice_call_waiting(&self) {
        self.call("onVoiceCallWaiting", &make_args!());
    }

    fn on_voice_call_incoming(&self) {
        self.call("onVoiceCallIncoming", &make_args!());
    }

    /// RGBA is directly rendered by [on_rgba]. No need to store the rgba for the sciter ui.
    fn get_rgba(&self, _display: usize) -> *const u8 {
        std::ptr::null()
    }

    fn next_rgba(&self, _display: usize) {}

    fn update_record_status(&self, start: bool) {
        self.call("updateRecordStatus", &make_args!(start));
    }

    fn printer_request(&self, id: i32, path: String) {
        self.call("printerRequest", &make_args!(id, path));
    }

    fn handle_screenshot_resp(&self, _sid: String, msg: String) {
        self.call("screenshot", &make_args!(msg));
    }

    fn handle_terminal_response(&self, _response: TerminalResponse) {
        // Terminal support is not implemented for Sciter UI
        // This is a stub implementation to satisfy the trait requirements
    }
}

pub struct SciterSession(Session<SciterHandler>);

impl Deref for SciterSession {
    type Target = Session<SciterHandler>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SciterSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl sciter::EventHandler for SciterSession {
    fn get_subscription(&mut self) -> Option<EVENT_GROUPS> {
        Some(EVENT_GROUPS::HANDLE_BEHAVIOR_EVENT)
    }

    fn attached(&mut self, root: HELEMENT) {
        let root = Element::from(root);
        SESSION_HWND.with(|h| h.set(Some(root.get_hwnd(true))));
        // Tiles get inert sessions of their own; only the session's real element is kept.
        if root.get_attribute("id").as_deref() == Some("handler") {
            SESSION_ELEMENT.with(|e| *e.borrow_mut() = Some(root.clone()));
        }
        *self.element.lock().unwrap() = Some(root);
    }

    fn detached(&mut self, _root: HELEMENT) {
        // Only the session that was actually started owns the display windows. The
        // inert sessions behind view-all tiles detach every time the tiles are rebuilt,
        // and must not take the user's other monitors down with them.
        let started = self.sender.read().unwrap().is_some();
        *self.element.lock().unwrap() = None;
        self.sender.write().unwrap().take().map(|sender| {
            sender.send(Data::Close).ok();
        });
        if started {
            close_all_display_windows();
            SESSION_ELEMENT.with(|e| *e.borrow_mut() = None);
        }
    }

    // https://github.com/sciter-sdk/rust-sciter/blob/master/examples/video.rs
    fn on_event(
        &mut self,
        _root: HELEMENT,
        source: HELEMENT,
        _target: HELEMENT,
        code: BEHAVIOR_EVENTS,
        phase: PHASE_MASK,
        reason: EventReason,
    ) -> bool {
        if phase != PHASE_MASK::BUBBLING {
            return false;
        }
        match code {
            BEHAVIOR_EVENTS::VIDEO_BIND_RQ => {
                let source = Element::from(source);
                log::debug!("[video] {:?} {} ({:?})", code, source, reason);
                if let EventReason::VideoBind(ptr) = reason {
                    if ptr.is_null() {
                        return true;
                    }
                    let site = AssetPtr::adopt(ptr as *mut video_destination);
                    log::debug!("[video] start video");
                    // A tile surface for "view all" mode is tagged `dispidx="N"`.
                    // The legacy single `<video #handler>` has no such attribute.
                    let disp_idx = source
                        .get_attribute("dispidx")
                        .and_then(|s| s.trim().parse::<usize>().ok());
                    match disp_idx {
                        Some(idx) => {
                            // A newly bound tile: store it and force a re-init on
                            // the next frame. Do NOT reconnect (session is live).
                            {
                                let mut lock = VIDEO.lock().unwrap();
                                lock.tile_dims.remove(&idx);
                                lock.tiles.insert(idx, site);
                                lock.tile_owner.insert(idx, 0);
                            }
                            // A fresh frame for the new surface: the one requested when
                            // the mode started may already have gone by (see the display
                            // window's bind), and a static remote screen sends no other.
                            self.refresh_video(idx as i32);
                        }
                        None => {
                            VIDEO.lock().unwrap().single = Some(site);
                            // This is THE session of this window: the only element that
                            // starts a connection. Make sure the keyboard follows it (see
                            // the CUR_SESSION note in ui.rs: tiles create inert sessions).
                            #[cfg(not(any(feature = "flutter", feature = "cli")))]
                            {
                                *crate::ui::CUR_SESSION.lock().unwrap() = Some(self.inner());
                            }
                            self.reconnect(false);
                        }
                    }
                }
            }
            BEHAVIOR_EVENTS::VIDEO_INITIALIZED => {
                log::debug!("[video] {:?}", code);
            }
            BEHAVIOR_EVENTS::VIDEO_STARTED => {
                log::debug!("[video] {:?}", code);
                let source = Element::from(source);
                use sciter::dom::ELEMENT_AREAS;
                let flags = ELEMENT_AREAS::CONTENT_BOX as u32 | ELEMENT_AREAS::SELF_RELATIVE as u32;
                let rc = source.get_location(flags).unwrap_or_default();
                log::debug!(
                    "[video] start video thread on <{}> which is about {:?} pixels",
                    source,
                    rc.size()
                );
            }
            BEHAVIOR_EVENTS::VIDEO_STOPPED => {
                log::debug!("[video] {:?}", code);
            }
            _ => return false,
        };
        return true;
    }

    sciter::dispatch_script_call! {
        fn get_audit_server(String);
        fn send_note(String);
        fn is_xfce();
        fn get_id();
        fn get_default_pi();
        fn get_option(String);
        fn t(String);
        fn set_option(String, String);
        fn input_os_password(String, bool);
        fn save_close_state(String, String);
        fn is_file_transfer();
        fn is_port_forward();
        fn is_rdp();
        fn login(String, String, String, bool);
        fn send2fa(String, bool);
        fn get_enable_trusted_devices();
        fn new_rdp();
        fn send_mouse(i32, i32, i32, bool, bool, bool, bool);
        fn enter(String);
        fn leave(String);
        fn ctrl_alt_del();
        fn transfer_file();
        fn tunnel();
        fn lock_screen();
        fn reconnect(bool);
        fn get_chatbox();
        fn get_icon();
        fn get_home_dir();
        fn get_next_job_id();
        fn update_next_job_id(i32);
        fn read_dir(String, bool);
        fn remove_dir(i32, String, bool);
        fn create_dir(i32, String, bool);
        fn remove_file(i32, String, i32, bool);
        fn read_remote_dir(String, bool);
        fn send_chat(String);
        fn switch_display(i32);
        fn set_view_all(String);
        fn open_display_window(i32, String, String, String);
        fn close_display_windows();
        fn remove_dir_all(i32, String, bool, bool);
        fn confirm_delete_files(i32, i32);
        fn set_no_confirm(i32);
        fn cancel_job(i32);
        fn send_files(i32, i32, String, String, i32, bool, bool);
        fn add_job(i32, i32, String, String, i32, bool, bool);
        fn resume_job(i32, bool);
        fn get_platform(bool);
        fn get_path_sep(bool);
        fn get_icon_path(i32, String);
        fn get_char(String, i32);
        fn get_size();
        fn get_port_forwards();
        fn remove_port_forward(i32);
        fn get_args();
        fn add_port_forward(i32, String, i32);
        fn save_size(i32, i32, i32, i32);
        fn get_view_style();
        fn get_image_quality();
        fn get_custom_image_quality();
        fn save_view_style(String);
        fn save_image_quality(String);
        fn save_custom_image_quality(i32);
        fn refresh_video(i32);
        fn record_screen(bool);
        fn is_screenshot_supported();
        fn take_screenshot(i32, String);
        fn handle_screenshot(String);
        fn get_toggle_option(String);
        fn is_privacy_mode_supported();
        fn toggle_option(String);
        fn toggle_privacy_mode(String, bool);
        fn get_remember();
        fn peer_platform();
        fn set_write_override(i32, i32, bool, bool, bool);
        fn get_keyboard_mode();
        fn is_keyboard_mode_supported(String);
        fn save_keyboard_mode(String);
        fn alternative_codecs();
        fn update_supported_decodings();
        fn restart_remote_device();
        fn request_voice_call();
        fn close_voice_call();
        fn version_cmp(String, String);
        fn set_selected_windows_session_id(String);
        fn is_recording();
        fn has_file_clipboard();
        fn get_printer_names();
        fn on_printer_selected(i32, String, String);
    }
}

impl SciterSession {
    pub fn new(cmd: String, id: String, password: String, args: Vec<String>) -> Self {
        let force_relay = args.contains(&"--relay".to_string());
        let session: Session<SciterHandler> = Session {
            password: password.clone(),
            args,
            server_keyboard_enabled: Arc::new(RwLock::new(true)),
            server_file_transfer_enabled: Arc::new(RwLock::new(true)),
            server_clipboard_enabled: Arc::new(RwLock::new(true)),
            reconnect_count: Arc::new(AtomicUsize::new(0)),
            ..Default::default()
        };

        let conn_type = if cmd.eq("--file-transfer") {
            ConnType::FILE_TRANSFER
        } else if cmd.eq("--view-camera") {
            ConnType::VIEW_CAMERA
        } else if cmd.eq("--port-forward") {
            ConnType::PORT_FORWARD
        } else if cmd.eq("--rdp") {
            ConnType::RDP
        } else {
            ConnType::DEFAULT_CONN
        };

        session
            .lc
            .write()
            .unwrap()
            .initialize(id, conn_type, None, force_relay, None, None, None);

        Self(session)
    }

    pub fn inner(&self) -> Session<SciterHandler> {
        self.0.clone()
    }

    fn get_custom_image_quality(&mut self) -> Value {
        let mut v = Value::array(0);
        for x in self.lc.read().unwrap().custom_image_quality.iter() {
            v.push(x);
        }
        v
    }

    pub fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    pub fn get_icon(&self) -> String {
        super::get_icon()
    }

    fn alternative_codecs(&self) -> Value {
        let (vp8, av1, h264, h265) = self.0.alternative_codecs();
        let mut v = Value::array(0);
        v.push(vp8);
        v.push(av1);
        v.push(h264);
        v.push(h265);
        v
    }

    fn save_size(&mut self, x: i32, y: i32, w: i32, h: i32) {
        let size = (x, y, w, h);
        let mut config = self.load_config();
        if self.is_file_transfer() {
            let close_state = self.close_state.clone();
            let mut has_change = false;
            for (k, mut v) in close_state {
                if k == "remote_dir" {
                    v = self.lc.read().unwrap().get_all_remote_dir(v);
                }
                let v2 = if v.is_empty() { None } else { Some(&v) };
                if v2 != config.options.get(&k) {
                    has_change = true;
                    if v2.is_none() {
                        config.options.remove(&k);
                    } else {
                        config.options.insert(k, v);
                    }
                }
            }
            if size == config.size_ft && !has_change {
                return;
            }
            config.size_ft = size;
        } else if self.is_port_forward() {
            if size == config.size_pf {
                return;
            }
            config.size_pf = size;
        } else {
            if size == config.size {
                return;
            }
            config.size = size;
        }
        self.save_config(config);
        log::info!("size saved");
    }

    fn set_selected_windows_session_id(&mut self, u_sid: String) {
        self.send_selected_session_id(u_sid);
    }

    /// Enter/exit the "view all displays" mode.
    ///
    /// `indices` is a comma-joined list of display indices to show tiled at once
    /// (e.g. "0,1,2"); an empty/blank string turns the mode off. Turning it on
    /// requests the peer to capture every listed display concurrently and asks
    /// for a refresh frame per display; the TIScript side is responsible for
    /// creating the matching `<video display="N">` tiles. Turning it off only
    /// clears the tile state here - the caller restores single-display capture
    /// via `switch_display`.
    fn set_view_all(&mut self, indices: String) {
        let all: Vec<i32> = indices
            .split(',')
            .filter_map(|s| s.trim().parse::<i32>().ok())
            .collect();
        if all.is_empty() {
            let mut lock = VIDEO.lock().unwrap();
            lock.view_all = false;
            lock.tiles.clear();
            lock.tile_dims.clear();
            lock.tile_owner.clear();
            return;
        }
        {
            let mut lock = VIDEO.lock().unwrap();
            lock.view_all = true;
            lock.tile_dims.clear();
        }
        self.capture_displays(vec![], vec![], all.clone());
        if crate::common::is_support_multi_ui_session_num(self.lc.read().unwrap().version) {
            for d in all.iter() {
                self.refresh_video(*d);
            }
        }
    }

    /// "One window per display": open a window for remote display `display` on the
    /// local monitor `monitor` ("x,y,w,h" in screen pixels). `remote` is that display's
    /// rect in the peer's desktop, for mouse mapping. The caller has already asked the
    /// peer to stream this display (set_view_all). Returns false when nothing opened.
    fn open_display_window(
        &mut self,
        display: i32,
        remote: String,
        monitor: String,
        title: String,
    ) -> bool {
        let (Some(r), Some(m)) = (parse_rect(&remote), parse_rect(&monitor)) else {
            log::error!("display window: bad rect remote={remote:?} monitor={monitor:?}");
            return false;
        };
        if display < 0 {
            return false;
        }
        let display = display as usize;
        // Re-opening the same display replaces its window rather than stacking two. Taken
        // out of the map BEFORE it is dismissed: where closing is synchronous, dismiss()
        // runs `detached`, which borrows the same map.
        let old = DISPLAY_WINDOWS.with(|w| w.borrow_mut().remove(&display));
        if let Some((_, old)) = old {
            old.dismiss();
        }
        let id = NEXT_DISPLAY_WINDOW_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let parent = SESSION_HWND.with(|h| h.get());
        let mut builder = sciter::WindowBuilder::with_flags(
            sciter::types::SCITER_CREATE_WINDOW_FLAGS::SW_TITLEBAR,
        )
        .resizeable()
        .closeable()
        .with_pos((m.0, m.1))
        .with_size((m.2, m.3));
        if let Some(p) = parent {
            builder = builder.with_parent(p);
        }
        let mut win = builder.create();
        let session = self.inner();
        win.register_behavior("native-display", move || {
            Box::new(DisplayWindowBehavior {
                session: session.clone(),
                display,
                id,
            })
        });
        win.set_title(&title);
        // BOM: see the main window's load_html in ui.rs -- the title is in the page and
        // may carry non-ASCII.
        if !win.load_html(
            format!("\u{feff}{}", display_window_html(r, &title)).as_bytes(),
            Some("display.html"),
        ) {
            log::error!("display window: failed to load page for display {display}");
            win.dismiss();
            return false;
        }
        win.expand(false);
        log::info!(
            "display window: remote display {} ({},{} {}x{}) on monitor {},{} {}x{}",
            display + 1, r.0, r.1, r.2, r.3, m.0, m.1, m.2, m.3
        );
        DISPLAY_WINDOWS.with(|w| w.borrow_mut().insert(display, (id, win)));
        true
    }

    fn close_display_windows(&mut self) {
        close_all_display_windows();
    }

    fn has_file_clipboard(&self) -> bool {
        cfg!(any(target_os = "windows", feature = "unix-file-copy-paste"))
    }

    fn get_port_forwards(&mut self) -> Value {
        let port_forwards = self.lc.read().unwrap().port_forwards.clone();
        let mut v = Value::array(0);
        for (port, remote_host, remote_port) in port_forwards {
            let mut v2 = Value::array(0);
            v2.push(port);
            v2.push(remote_host);
            v2.push(remote_port);
            v.push(v2);
        }
        v
    }

    fn get_args(&mut self) -> Value {
        let mut v = Value::array(0);
        for x in self.args.iter() {
            v.push(x);
        }
        v
    }

    fn get_size(&mut self) -> Value {
        let s = if self.is_file_transfer() {
            self.lc.read().unwrap().size_ft
        } else if self.is_port_forward() {
            self.lc.read().unwrap().size_pf
        } else {
            self.lc.read().unwrap().size
        };
        let mut v = Value::array(0);
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        v
    }

    fn get_default_pi(&mut self) -> Value {
        let mut pi = Value::map();
        let info = self.lc.read().unwrap().info.clone();
        pi.set_item("username", info.username.clone());
        pi.set_item("hostname", info.hostname.clone());
        pi.set_item("platform", info.platform.clone());
        pi
    }

    fn save_close_state(&mut self, k: String, v: String) {
        self.close_state.insert(k, v);
    }

    fn get_key_event(&self, down_or_up: i32, name: &str, code: i32) -> Option<KeyEvent> {
        let mut key_event = KeyEvent::new();
        if down_or_up == 2 {
            /* windows send both keyup/keydown and keychar, so here we avoid keychar
               for <= 0xFF, best practice should only avoid those not on keyboard, but
               for now, we have no way to test, so avoid <= 0xFF totally
            */
            if code <= 0xFF {
                return None;
            }
            key_event.set_unicode(code.clone() as _);
        } else if let Some(key) = KEY_MAP.get(name) {
            match key {
                Key::Chr(chr) => {
                    key_event.set_chr(chr.clone());
                }
                Key::ControlKey(key) => {
                    key_event.set_control_key(key.clone());
                }
                _ => {}
            }
        } else {
            if cfg!(target_os = "macos") {
                match code {
                    0x4C => key_event.set_control_key(ControlKey::NumpadEnter), // numpad enter
                    0x69 => key_event.set_control_key(ControlKey::Snapshot),
                    0x72 => key_event.set_control_key(ControlKey::Help),
                    0x6E => key_event.set_control_key(ControlKey::Apps),
                    0x47 => {
                        key_event.set_control_key(if self.peer_platform() == "Mac OS" {
                            ControlKey::Clear
                        } else {
                            ControlKey::NumLock
                        });
                    }
                    0x51 => key_event.set_control_key(ControlKey::Equals),
                    0x2F => key_event.set_chr('.' as _),
                    0x32 => key_event.set_chr('`' as _),
                    _ => {
                        log::error!("Unknown key code {}", code);
                        return None;
                    }
                }
            } else if cfg!(windows) {
                match code {
                    0x2C => key_event.set_control_key(ControlKey::Snapshot),
                    0x91 => key_event.set_control_key(ControlKey::Scroll),
                    0x90 => key_event.set_control_key(ControlKey::NumLock),
                    0x5C => key_event.set_control_key(ControlKey::RWin),
                    0x5B => key_event.set_control_key(ControlKey::Meta),
                    0x5D => key_event.set_control_key(ControlKey::Apps),
                    0xBE => key_event.set_chr('.' as _),
                    0xC0 => key_event.set_chr('`' as _),
                    _ => {
                        log::error!("Unknown key code {}", code);
                        return None;
                    }
                }
            } else if cfg!(target_os = "linux") {
                match code {
                    65300 => key_event.set_control_key(ControlKey::Scroll),
                    65421 => key_event.set_control_key(ControlKey::NumpadEnter), // numpad enter
                    65407 => key_event.set_control_key(ControlKey::NumLock),
                    65515 => key_event.set_control_key(ControlKey::Meta),
                    65516 => key_event.set_control_key(ControlKey::RWin),
                    65513 => key_event.set_control_key(ControlKey::Alt),
                    65514 => key_event.set_control_key(ControlKey::RAlt),
                    65508 => key_event.set_control_key(ControlKey::RControl),
                    65506 => key_event.set_control_key(ControlKey::RShift),
                    96 => key_event.set_chr('`' as _),
                    46 => key_event.set_chr('.' as _),
                    126 => key_event.set_chr('`' as _),
                    33 => key_event.set_chr('1' as _),
                    64 => key_event.set_chr('2' as _),
                    35 => key_event.set_chr('3' as _),
                    36 => key_event.set_chr('4' as _),
                    37 => key_event.set_chr('5' as _),
                    94 => key_event.set_chr('6' as _),
                    38 => key_event.set_chr('7' as _),
                    42 => key_event.set_chr('8' as _),
                    40 => key_event.set_chr('9' as _),
                    41 => key_event.set_chr('0' as _),
                    95 => key_event.set_chr('-' as _),
                    43 => key_event.set_chr('=' as _),
                    123 => key_event.set_chr('[' as _),
                    125 => key_event.set_chr(']' as _),
                    124 => key_event.set_chr('\\' as _),
                    58 => key_event.set_chr(';' as _),
                    34 => key_event.set_chr('\'' as _),
                    60 => key_event.set_chr(',' as _),
                    62 => key_event.set_chr('.' as _),
                    63 => key_event.set_chr('/' as _),
                    _ => {
                        log::error!("Unknown key code {}", code);
                        return None;
                    }
                }
            } else {
                log::error!("Unknown key code {}", code);
                return None;
            }
        }
        Some(key_event)
    }

    fn get_char(&mut self, name: String, code: i32) -> String {
        if let Some(key_event) = self.get_key_event(1, &name, code) {
            match key_event.union {
                Some(key_event::Union::Chr(chr)) => {
                    if let Some(chr) = std::char::from_u32(chr as _) {
                        return chr.to_string();
                    }
                }
                _ => {}
            }
        }
        "".to_owned()
    }

    fn transfer_file(&mut self) {
        let id = self.get_id();
        let args = vec!["--file-transfer", &id, &self.password];
        if let Err(err) = crate::run_me(args) {
            log::error!("Failed to spawn file transfer: {}", err);
        }
    }

    fn tunnel(&mut self) {
        let id = self.get_id();
        let args = vec!["--port-forward", &id, &self.password];
        if let Err(err) = crate::run_me(args) {
            log::error!("Failed to spawn IP tunneling: {}", err);
        }
    }

    fn version_cmp(&self, v1: String, v2: String) -> i32 {
        (hbb_common::get_version_number(&v1) - hbb_common::get_version_number(&v2)) as i32
    }

    fn get_printer_names(&self) -> Value {
        #[cfg(target_os = "windows")]
        let printer_names = crate::platform::windows::get_printer_names().unwrap_or_default();
        #[cfg(not(target_os = "windows"))]
        let printer_names: Vec<String> = vec![];
        let mut v = Value::array(0);
        for name in printer_names {
            v.push(name);
        }
        v
    }

    fn on_printer_selected(&self, id: i32, path: String, printer_name: String) {
        self.printer_response(id, path, printer_name);
    }

    fn handle_screenshot(&self, action: String) -> String {
        crate::client::screenshot::handle_screenshot(action)
    }
}

pub fn make_fd(id: i32, entries: &Vec<FileEntry>, only_count: bool) -> Value {
    let mut m = Value::map();
    m.set_item("id", id);
    let mut a = Value::array(0);
    let mut n: u64 = 0;
    for entry in entries {
        n += entry.size;
        if only_count {
            continue;
        }
        let mut e = Value::map();
        e.set_item("name", entry.name.to_owned());
        let tmp = entry.entry_type.value();
        e.set_item("type", if tmp == 0 { 1 } else { tmp });
        e.set_item("time", entry.modified_time as f64);
        e.set_item("size", entry.size as f64);
        a.push(e);
    }
    if !only_count {
        m.set_item("entries", a);
    }
    m.set_item("num_entries", entries.len() as i32);
    m.set_item("total_size", n as f64);
    m
}
