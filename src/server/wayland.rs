use super::*;
use hbb_common::{allow_err, anyhow, platform::linux::DISTRO};
use scrap::{
    is_cursor_embedded, set_map_err,
    wayland::pipewire::{fill_displays, try_fix_logical_size},
    Capturer, Display, Frame, TraitCapturer,
};
use std::collections::HashMap;
use std::io;

use crate::{
    client::{
        SCRAP_OTHER_VERSION_OR_X11_REQUIRED, SCRAP_UBUNTU_HIGHER_REQUIRED,
        SCRAP_X11_REQUIRED, SCRAP_XDP_PORTAL_UNAVAILABLE,
    },
    platform::linux::is_x11,
};

lazy_static::lazy_static! {
    static ref CAP_DISPLAY_INFO: RwLock<HashMap<usize, u64>> = RwLock::new(HashMap::new());
    static ref PIPEWIRE_INITIALIZED: RwLock<bool> = RwLock::new(false);
    static ref LOG_SCRAP_COUNT: Mutex<u32> = Mutex::new(0);
    static ref ACTIVE_DISPLAY_COUNT: RwLock<usize> = RwLock::new(0);
}

pub fn init() {
    set_map_err(map_err_scrap);
}

pub(super) fn increment_active_display_count() -> usize {
    let mut count = ACTIVE_DISPLAY_COUNT.write().unwrap();
    *count += 1;
    *count
}

pub(super) fn decrement_active_display_count() -> usize {
    let mut count = ACTIVE_DISPLAY_COUNT.write().unwrap();
    if *count > 0 {
        *count -= 1;
    }
    *count
}

fn map_err_scrap(err: String) -> io::Error {
    // to-do: Handle error better, do not restart server
    if err.starts_with("Did not receive a reply") {
        log::error!("Fatal pipewire error, {}", &err);
        std::process::exit(-1);
    }

    if DISTRO.name.to_uppercase() == "Ubuntu".to_uppercase() {
        if DISTRO.version_id < "21".to_owned() {
            io::Error::new(io::ErrorKind::Other, SCRAP_UBUNTU_HIGHER_REQUIRED)
        } else {
            try_log(&err);
            io::Error::new(io::ErrorKind::Other, err)
        }
    } else {
        try_log(&err);
        let err_lower = err.to_ascii_lowercase();
        if err_lower.contains("org.freedesktop.portal")
            || err_lower.contains("dbus")
            || err_lower.contains("d-bus")
        {
            // The portal D-Bus interface is unreachable. This typically means
            // xdg-desktop-portal has crashed... for more info, see: Issue #12897
            io::Error::new(io::ErrorKind::Other, SCRAP_XDP_PORTAL_UNAVAILABLE)
        } else if err_lower.contains("pipewire") {
            io::Error::new(io::ErrorKind::Other, SCRAP_OTHER_VERSION_OR_X11_REQUIRED)
        } else {
            io::Error::new(io::ErrorKind::Other, SCRAP_X11_REQUIRED)
        }
    }
}

fn try_log(err: &String) {
    let mut lock_count = LOG_SCRAP_COUNT.lock().unwrap();
    if *lock_count >= 1000000 {
        return;
    }
    if *lock_count % 10000 == 0 {
        log::error!("Failed scrap {}", err);
    }
    *lock_count += 1;
}

struct CapturerPtr(*mut Capturer);

impl Clone for CapturerPtr {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl TraitCapturer for CapturerPtr {
    fn frame<'a>(&'a mut self, timeout: std::time::Duration) -> std::io::Result<Frame<'a>> {
        unsafe { (*self.0).frame(timeout) }
    }
}

struct CapDisplayInfo {
    rects: Vec<((i32, i32), usize, usize)>,
    displays: Vec<DisplayInfo>,
    num: usize,
    primary: usize,
    current: usize,
    capturer: CapturerPtr,
}

#[tokio::main(flavor = "current_thread")]
pub(super) async fn ensure_inited() -> ResultType<()> {
    check_init().await
}

/// TBFDesk: the displays for a login, with the whole capture set-up -- the
/// xdg-desktop-portal handshake, which waits for the local user to answer GNOME's
/// "share your screen" dialog (up to 3 minutes, pipewire.rs `request_remote_desktop`)
/// -- run to completion on the calling thread. Called from the dedicated thread the
/// connection starts at login (connection.rs, `start_wayland_portal_wait`). It used to
/// run on the connection's own tokio task, inside its select loop: no heartbeat was read
/// or answered during the dialog, and once the user clicked Share the loop's 30 s check
/// closed the session with "Timeout" in the same second.
#[tokio::main(flavor = "current_thread")]
pub(super) async fn get_displays_blocking() -> ResultType<Vec<DisplayInfo>> {
    get_displays().await
}

/// TBFDesk: the text of the box the controller sees while the local user still has to
/// answer the portal's screen-sharing dialog. The controller translates it (en.rs, de.rs),
/// so it is the English sentence itself: older controllers show it as it is.
pub(super) const PORTAL_WAIT_TEXT: &str = "Waiting for the remote user to allow screen sharing...";

/// TBFDesk: the box for `PORTAL_WAIT_TEXT`. "wait-remote-accept-nook" is the existing
/// "waiting for the other side" box (also used while a session request waits for the
/// remote user to accept it): an hourglass and a Cancel that ends the session, the same
/// in Sciter (common.tis msgbox) and Flutter desktop and Android (model.dart
/// showWaitAcceptDialog). It replaces upstream's "nook-nocancel-hasclose" box, whose
/// Close ended the session in Sciter but only hid the box in Flutter.
pub(super) fn portal_wait_msg() -> Message {
    let mut msg_out = Message::new();
    msg_out.set_message_box(MessageBox {
        msgtype: "wait-remote-accept-nook".to_owned(),
        title: "Prompt".to_owned(),
        text: PORTAL_WAIT_TEXT.to_owned(),
        link: "".to_owned(),
        ..Default::default()
    });
    msg_out
}

pub(super) async fn check_init() -> ResultType<()> {
    if !is_x11() {
        if CAP_DISPLAY_INFO.read().unwrap().is_empty() {
            if crate::input_service::wayland_use_uinput() {
                if let Some((minx, maxx, miny, maxy)) =
                    scrap::wayland::display::get_desktop_rect_for_uinput()
                {
                    log::info!(
                        "update mouse resolution: ({}, {}), ({}, {})",
                        minx,
                        maxx,
                        miny,
                        maxy
                    );
                    allow_err!(
                        input_service::update_mouse_resolution(minx, maxx, miny, maxy).await
                    );
                } else {
                    log::warn!("Failed to get desktop rect for uinput");
                }
            }

            let mut lock = CAP_DISPLAY_INFO.write().unwrap();
            if lock.is_empty() {
                // Check if PipeWire is already initialized to prevent duplicate recorder creation
                if *PIPEWIRE_INITIALIZED.read().unwrap() {
                    log::warn!("wayland_diag: Preventing duplicate PipeWire initialization");
                    return Ok(());
                }

                let mut all = Display::all()?;
                log::debug!("Initializing displays with fill_displays()");
                {
                    let temp_mouse_move_handle = input_service::TemporaryMouseMoveHandle::new();
                    let move_mouse_to = |x, y| temp_mouse_move_handle.move_mouse_to(x, y);
                    fill_displays(move_mouse_to, crate::get_cursor_pos, &mut all)?;
                }
                log::debug!("Attempting to fix logical size with try_fix_logical_size()");
                try_fix_logical_size(&mut all);
                *PIPEWIRE_INITIALIZED.write().unwrap() = true;
                let num = all.len();
                let primary = super::display_service::get_primary_2(&all);
                super::display_service::check_update_displays(&all);
                let mut displays = super::display_service::get_sync_displays();
                for display in displays.iter_mut() {
                    display.cursor_embedded = is_cursor_embedded();
                }

                let mut rects: Vec<((i32, i32), usize, usize)> = Vec::new();
                for d in &all {
                    rects.push((d.origin(), d.width(), d.height()));
                }

                log::debug!(
                    "#displays={}, primary={}, rects: {:?}, cpus={}/{}",
                    num,
                    primary,
                    rects,
                    num_cpus::get_physical(),
                    num_cpus::get()
                );

                // Create individual CapDisplayInfo for each display with its own capturer
                for (idx, display) in all.into_iter().enumerate() {
                    let capturer =
                        Box::into_raw(Box::new(Capturer::new(display).with_context(|| {
                            format!("Failed to create capturer for display {}", idx)
                        })?));
                    let capturer = CapturerPtr(capturer);

                    let cap_display_info = Box::into_raw(Box::new(CapDisplayInfo {
                        rects: rects.clone(),
                        displays: displays.clone(),
                        num,
                        primary,
                        current: idx,
                        capturer,
                    }));

                    lock.insert(idx, cap_display_info as u64);
                }
            }
        }
    }
    Ok(())
}

pub(super) async fn get_displays() -> ResultType<Vec<DisplayInfo>> {
    check_init().await?;
    let cap_map = CAP_DISPLAY_INFO.read().unwrap();
    if let Some(addr) = cap_map.values().next() {
        let cap_display_info: *const CapDisplayInfo = *addr as _;
        unsafe {
            let cap_display_info = &*cap_display_info;
            Ok(cap_display_info.displays.clone())
        }
    } else {
        bail!("Failed to get capturer display info");
    }
}

pub(super) fn get_primary() -> ResultType<usize> {
    let cap_map = CAP_DISPLAY_INFO.read().unwrap();
    if let Some(addr) = cap_map.values().next() {
        let cap_display_info: *const CapDisplayInfo = *addr as _;
        unsafe {
            let cap_display_info = &*cap_display_info;
            Ok(cap_display_info.primary)
        }
    } else {
        bail!("Failed to get capturer display info");
    }
}

pub fn clear() {
    if is_x11() {
        return;
    }
    let mut write_lock = CAP_DISPLAY_INFO.write().unwrap();
    clear_locked(&mut write_lock);
}

/// TBFDesk: free the capturers set up for a session that ended before it used them --
/// the controller gave up while the local user still had the share dialog open, and the
/// user clicked Share afterwards. Left alone they would keep the screen cast (and GNOME's
/// "screen is being shared" indicator) running with nobody watching until the next
/// session. The write lock is taken before the video-service count is read, so a video
/// service starting at the same moment is either counted already (nothing is freed) or
/// finds the map empty afterwards (its get_capturer_for_display fails with an error);
/// it never holds a pointer freed here. The caller has also made sure no other remote
/// session is open, so no video service should be starting at all. Returns whether
/// anything was freed.
pub(super) fn clear_if_unused() -> bool {
    if is_x11() {
        return false;
    }
    let mut write_lock = CAP_DISPLAY_INFO.write().unwrap();
    if write_lock.is_empty() || *ACTIVE_DISPLAY_COUNT.read().unwrap() > 0 {
        return false;
    }
    clear_locked(&mut write_lock);
    true
}

fn clear_locked(cap_display_info_map: &mut HashMap<usize, u64>) {
    for (_, addr) in cap_display_info_map.iter() {
        let cap_display_info: *mut CapDisplayInfo = *addr as _;
        unsafe {
            let _box_capturer = Box::from_raw((*cap_display_info).capturer.0);
            let _box_cap_display_info = Box::from_raw(cap_display_info);
        }
    }
    cap_display_info_map.clear();

    // Reset PipeWire initialization flag to allow recreation on next init
    *PIPEWIRE_INITIALIZED.write().unwrap() = false;
}

pub(super) fn get_capturer_for_display(
    display_idx: usize,
) -> ResultType<super::video_service::CapturerInfo> {
    if is_x11() {
        bail!("Do not call this function if not wayland");
    }
    let cap_map = CAP_DISPLAY_INFO.read().unwrap();
    if let Some(addr) = cap_map.get(&display_idx) {
        let cap_display_info: *const CapDisplayInfo = *addr as _;
        unsafe {
            let cap_display_info = &*cap_display_info;
            let rect = cap_display_info.rects[cap_display_info.current];
            Ok(super::video_service::CapturerInfo {
                origin: rect.0,
                width: rect.1,
                height: rect.2,
                ndisplay: cap_display_info.num,
                current: cap_display_info.current,
                privacy_mode_id: 0,
                _capturer_privacy_mode_id: 0,
                capturer: Box::new(cap_display_info.capturer.clone()),
            })
        }
    } else {
        bail!(
            "Failed to get capturer display info for display {}",
            display_idx
        );
    }
}

pub fn common_get_error() -> String {
    if DISTRO.name.to_uppercase() == "Ubuntu".to_uppercase() {
        if DISTRO.version_id < "21".to_owned() {
            return "".to_owned();
        }
    } else {
        // to-do: check other distros
    }
    return "".to_owned();
}
