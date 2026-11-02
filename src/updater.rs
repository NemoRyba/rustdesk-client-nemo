use crate::{common::do_check_software_update, hbbs_http::create_http_client_with_url};
use hbb_common::{bail, config, log, ResultType};
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    time::{Duration, Instant},
};

enum UpdateMsg {
    CheckUpdate,
    Exit,
}

lazy_static::lazy_static! {
    static ref TX_MSG : Mutex<Sender<UpdateMsg>> = Mutex::new(start_auto_update_check());
}

static CONTROLLING_SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);

// The user's side of an update, carried to this (service) process as options through the
// UI's settings channel:
// - the pre-install prompt's answer, "<now|postpone>:<version>:<unix ts>";
// - the main window's "install now" button, "<version>:<unix ts>".
pub const OPTION_UPDATE_DECISION: &str = "nemo-update-decision";
pub const OPTION_UPDATE_REQUEST: &str = "nemo-update-request";
const PROMPT_SECS: u64 = 60;
const POSTPONE: Duration = Duration::from_secs(60 * 60);
// After this many postponements of one version the prompt only informs: the update
// still never runs during a session, but a user cannot hold it back for ever.
const MAX_POSTPONES: u32 = 4;
// (version, postponements so far, postponed until)
static POSTPONED: Mutex<(String, u32, Option<Instant>)> = Mutex::new((String::new(), 0, None));

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// User-configurable check interval (Settings → General → Auto update), stored
// in SECONDS in the "auto-update-check-interval" option; default one day.
// Allowed range: 1 to 30 days. NOTE: the whole feature is dormant until the
// TBF update server exists (OPEN-TODOS HIGH #1) — the Settings row is greyed.
fn get_check_interval() -> Duration {
    const DAY: u64 = 60 * 60 * 24;
    let secs = config::Config::get_option("auto-update-check-interval")
        .parse::<u64>()
        .ok()
        .filter(|s| (DAY..=DAY * 30).contains(s))
        .unwrap_or(DAY);
    Duration::from_secs(secs)
}

pub fn update_controlling_session_count(count: usize) {
    CONTROLLING_SESSION_COUNT.store(count, Ordering::SeqCst);
}

#[allow(dead_code)]
pub fn start_auto_update() {
    let _sender = TX_MSG.lock().unwrap();
}

#[allow(dead_code)]
pub fn manually_check_update() -> ResultType<()> {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::CheckUpdate)?;
    Ok(())
}

#[allow(dead_code)]
pub fn stop_auto_update() {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::Exit).unwrap_or_default();
}

#[inline]
fn has_no_active_conns() -> bool {
    let conns = crate::Connection::alive_conns();
    conns.is_empty() && has_no_controlling_conns()
}

#[cfg(any(all(not(target_os = "windows"), not(target_os = "linux")), feature = "flutter"))]
fn has_no_controlling_conns() -> bool {
    CONTROLLING_SESSION_COUNT.load(Ordering::SeqCst) == 0
}

// Linux: this root service process does not see the user's session windows (separate
// processes), so look for them the way the Windows variant does.
#[cfg(all(target_os = "linux", not(feature = "flutter")))]
fn has_no_controlling_conns() -> bool {
    const SESSION_ARGS: &[&str] = &[
        "--connect",
        "--play",
        "--file-transfer",
        "--view-camera",
        "--port-forward",
        "--rdp",
    ];
    let me = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_default();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return true;
    };
    for e in dir.flatten() {
        let Ok(cmdline) = std::fs::read(e.path().join("cmdline")) else {
            continue;
        };
        let mut argv = cmdline.split(|b| *b == 0);
        let (Some(a0), Some(a1)) = (argv.next(), argv.next()) else {
            continue;
        };
        let a0 = String::from_utf8_lossy(a0);
        let name = a0.rsplit('/').next().unwrap_or("");
        let a1 = String::from_utf8_lossy(a1);
        if (name == me || name == "rustdesk" || name == "tbfdesk") && SESSION_ARGS.contains(&a1.as_ref()) {
            return false;
        }
    }
    true
}

#[cfg(not(any(not(target_os = "windows"), feature = "flutter")))]
fn has_no_controlling_conns() -> bool {
    let app_exe = format!("{}.exe", crate::get_app_name().to_lowercase());
    for arg in [
        "--connect",
        "--play",
        "--file-transfer",
        "--view-camera",
        "--port-forward",
        "--rdp",
    ] {
        if !crate::platform::get_pids_of_process_with_first_arg(&app_exe, arg).is_empty() {
            return false;
        }
    }
    true
}

fn start_auto_update_check() -> Sender<UpdateMsg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || start_auto_update_check_(rx));
    return tx;
}

fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {
    std::thread::sleep(Duration::from_secs(30));
    if let Err(e) = check_update(false, false) {
        log::error!("Error checking for updates: {}", e);
    }

    const MIN_MANUAL_INTERVAL: Duration = Duration::from_secs(60 * 10);
    const MIN_RETRY: Duration = Duration::from_secs(60);
    const MAX_RETRY: Duration = Duration::from_secs(60 * 30);
    // Wake at least this often so a changed "auto-update-check-interval" takes
    // effect without restarting, and so the main window's "install now" is answered
    // within a minute; a check only runs when it is actually due.
    const POLL_INTERVAL: Duration = Duration::from_secs(60);
    let mut last_check_time = Instant::now();
    let mut retry_not_before = Instant::now();
    // A requested check (the server published a new version) that could not run yet --
    // too soon after the last check, or a session was open -- stays pending and runs
    // at the next wake-up that allows it, instead of waiting for the daily check.
    let mut pending_manual = false;
    // "Install now" from the main window: asked by the user, so neither the 10-minute
    // spacing nor the retry back-off applies, and no prompt is shown -- only the rule
    // that no session may be open. A request left over from before a restart is not
    // replayed.
    let mut last_request = config::Config::get_option(OPTION_UPDATE_REQUEST);
    let mut user_requested = false;
    loop {
        let interval = get_check_interval();
        let recv_res = rx_msg.recv_timeout(POLL_INTERVAL.min(interval));
        match &recv_res {
            Ok(UpdateMsg::CheckUpdate) | Err(_) => {
                if matches!(recv_res, Ok(UpdateMsg::CheckUpdate)) {
                    pending_manual = true;
                }
                let request = config::Config::get_option(OPTION_UPDATE_REQUEST);
                if !request.is_empty() && request != last_request {
                    log::info!("Update requested from the main window ({})", request);
                    last_request = request;
                    pending_manual = true;
                    user_requested = true;
                }
                let manually = pending_manual;
                if manually && !user_requested {
                    if last_check_time.elapsed() < MIN_MANUAL_INTERVAL
                        || Instant::now() < retry_not_before
                    {
                        // log::debug!("Update check skipped due to minimum interval.");
                        continue;
                    }
                } else if Instant::now() < retry_not_before
                    || last_check_time.elapsed() < interval
                {
                    continue;
                }
                // Don't check update if there are alive connections.
                if !has_no_active_conns() {
                    retry_not_before = Instant::now() + interval.clamp(MIN_RETRY, MAX_RETRY);
                    continue;
                }
                pending_manual = false;
                let asked = std::mem::take(&mut user_requested);
                if let Err(e) = check_update(manually, asked) {
                    log::error!("Error checking for updates: {}", e);
                    retry_not_before = Instant::now() + interval.clamp(MIN_RETRY, MAX_RETRY);
                    // A pushed update that failed or had to wait for a session to end is
                    // retried (at most every MAX_RETRY), not dropped until tomorrow.
                    pending_manual = manually;
                } else {
                    last_check_time = Instant::now();
                }
            }
            Ok(UpdateMsg::Exit) => break,
        }
    }
}

fn check_update(manually: bool, user_requested: bool) -> ResultType<()> {
    #[cfg(target_os = "windows")]
    let update_msi = crate::platform::is_msi_installed()? && !crate::is_custom_client();
    // Auto-update: the ONLY switch for our updater is the Nemo policy key
    // "nemo-auto-update" == "Y" (or a manual check). The stock `allow-auto-update`
    // is refused from policy (nemo_management_client POLICY_DENIED_KEYS) and must
    // never reach this gate, or a pushed policy could re-enable the upstream path.
    if !(manually || config::Config::get_option("nemo-auto-update") == "Y") {
        return Ok(());
    }
    if do_check_software_update().is_err() {
        // ignore
        return Ok(());
    }

    // Auto-update: SOFTWARE_UPDATE_URL is the `url` of a manifest that
    // do_check_software_update has already verified (management-key signature over
    // "version|url|sha256", url on the management-server origin) and
    // NEMO_UPDATE_SHA256 is that manifest's `sha256`. The upstream "tag"->"download"
    // rewrite and the rustdesk-<v>-x86-sciter.exe naming are gone: they pointed at
    // github.com/rustdesk, which our server cannot sign for.
    let download_url = crate::common::SOFTWARE_UPDATE_URL.lock().unwrap().clone();
    if download_url.is_empty() {
        log::debug!("No update available.");
    } else {
        let expected_sha256 = crate::common::NEMO_UPDATE_SHA256
            .lock()
            .unwrap()
            .trim()
            .to_owned();
        if expected_sha256.is_empty() {
            // Never fetch, let alone install, an artifact we cannot verify.
            bail!(
                "Update manifest carries no sha256, refusing to download {}",
                download_url
            );
        }
        // Log-only: the artifact's file name stands in for the version string.
        let version = download_url.split('/').last().unwrap_or_default();
        log::debug!("New version available: {}", &version);
        let offered = crate::common::NEMO_UPDATE_VERSION.lock().unwrap().clone();
        if !user_requested {
            let p = POSTPONED.lock().unwrap();
            if p.0 == offered && p.2.map_or(false, |until| Instant::now() < until) {
                bail!("the user postponed {} (until about an hour after asking)", offered);
            }
        }
        // The installer comes from the management server. With its certificate pinned
        // (nemo-api-cert-fingerprint) the download uses that pin like the policy poll and
        // the manifest do, and never the accept-any-certificate fallback, so a man in the
        // middle can neither read it nor serve it. Integrity still rests on the signed
        // sha256 checked below; without a pin the old behaviour stands.
        let pin = crate::common::nemo_pin_for_url(&download_url);
        log::info!(
            "Nemo update download over {} TLS",
            if pin.is_some() { "PINNED" } else { "unpinned" }
        );
        let client = match pin {
            Some(fp) => crate::hbbs_http::create_http_client_pinned(fp),
            None => create_http_client_with_url(&download_url),
        };
        let Some(file_path) = get_download_file_from_url(&download_url) else {
            bail!("Failed to get the file path from the URL: {}", download_url);
        };
        let mut is_file_exists = false;
        if file_path.exists() {
            // Check if the file size is the same as the server file size
            // If the file size is the same, we don't need to download it again.
            let file_size = std::fs::metadata(&file_path)?.len();
            let response = client.head(&download_url).send()?;
            if !response.status().is_success() {
                bail!("Failed to get the file size: {}", response.status());
            }
            let total_size = response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|ct_len| ct_len.to_str().ok())
                .and_then(|ct_len| ct_len.parse::<u64>().ok());
            let Some(total_size) = total_size else {
                bail!("Failed to get content length");
            };
            if file_size == total_size {
                is_file_exists = true;
            } else {
                std::fs::remove_file(&file_path)?;
            }
        }
        if !is_file_exists {
            let response = client.get(&download_url).send()?;
            if !response.status().is_success() {
                bail!(
                    "Failed to download the new version file: {}",
                    response.status()
                );
            }
            let file_data = response.bytes()?;
            let mut file = std::fs::File::create(&file_path)?;
            file.write_all(&file_data)?;
        }
        // Auto-update: verify the on-disk artifact against the manifest's SHA-256
        // before the privileged installer ever sees it. Hashing the file (not the
        // response body) also covers the same-size short-circuit above, where a stale
        // or replaced temp file is reused without a download. A mismatch deletes the
        // file so the retry loop re-downloads instead of re-trying a poisoned one.
        let actual_sha256 = sha256_hex_of_file(&file_path)?;
        if !actual_sha256.eq_ignore_ascii_case(&expected_sha256) {
            if let Err(e) = std::fs::remove_file(&file_path) {
                log::error!(
                    "Failed to remove update file with bad hash {:?}: {}",
                    file_path,
                    e
                );
            }
            bail!(
                "SHA-256 mismatch for {}: manifest {}, downloaded {}",
                download_url,
                expected_sha256,
                actual_sha256
            );
        }
        // We have checked if the `conns` is empty before, but we need to check again.
        // No need to care about the downloaded file here, because it's rare case that the `conns` are empty
        // before the download, but not empty after the download.
        if !has_no_active_conns() {
            // Downloaded and verified; installed after the session (see the retry).
            bail!("a session started during the download; installing {} later", version);
        }
        // Ask whoever is at the computer first, unless they asked for it themselves.
        if !user_requested {
            if let PromptAnswer::Postpone = prompt_user(&offered) {
                let mut p = POSTPONED.lock().unwrap();
                let count = if p.0 == offered { p.1 + 1 } else { 1 };
                *p = (offered.clone(), count, Some(Instant::now() + POSTPONE));
                bail!("the user postponed {} by an hour ({} of {})", offered, count, MAX_POSTPONES);
            }
            if !has_no_active_conns() {
                bail!("a session started while asking; installing {} later", offered);
            }
        }
        #[cfg(target_os = "windows")]
        update_new_version(update_msi, &version, &file_path);
        #[cfg(target_os = "linux")]
        update_new_version_linux(&file_path)?;
    }
    Ok(())
}

enum PromptAnswer {
    Install,
    Postpone,
}

/// Show the logged-in user a 60-second "TBFDesk will now be updated" prompt (a small
/// window started in their session, `--nemo-update-prompt`) and wait for the answer it
/// sends back as OPTION_UPDATE_DECISION. No user session, no answer, or the countdown
/// running out all mean Install: an unattended machine must still update.
fn prompt_user(version: &str) -> PromptAnswer {
    let allow_postpone = {
        let p = POSTPONED.lock().unwrap();
        p.0 != version || p.1 < MAX_POSTPONES
    };
    let started = now_secs();
    config::Config::set_option(OPTION_UPDATE_DECISION.to_owned(), String::new());
    let secs = PROMPT_SECS.to_string();
    let args = vec![
        "--nemo-update-prompt",
        version,
        if allow_postpone { "1" } else { "0" },
        &secs,
    ];
    #[cfg(target_os = "windows")]
    let launched = crate::platform::run_as_user(args).map(|_| ());
    #[cfg(target_os = "linux")]
    let launched = crate::platform::run_as_user(args, None, None::<(&str, &str)>).map(|_| ());
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let launched: ResultType<()> = {
        let _ = args;
        Err(hbb_common::anyhow::anyhow!("no update prompt on this platform"))
    };
    if let Err(e) = launched {
        log::info!("Nobody to ask about update {} ({}); installing", version, e);
        return PromptAnswer::Install;
    }
    log::info!("Asking the user about update {} ({} s)", version, PROMPT_SECS);
    let deadline = Instant::now() + Duration::from_secs(PROMPT_SECS + 5);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let answer = config::Config::get_option(OPTION_UPDATE_DECISION);
        let mut parts = answer.splitn(3, ':');
        if let (Some(choice), Some(v), Some(ts)) = (parts.next(), parts.next(), parts.next()) {
            if v == version && ts.parse::<u64>().unwrap_or(0) >= started {
                config::Config::set_option(OPTION_UPDATE_DECISION.to_owned(), String::new());
                log::info!("The user answered '{}' for update {}", choice, version);
                if choice == "postpone" && allow_postpone {
                    return PromptAnswer::Postpone;
                }
                return PromptAnswer::Install;
            }
        }
    }
    log::info!("No answer about update {} within {} s; installing", version, PROMPT_SECS);
    PromptAnswer::Install
}

/// Linux: install the verified package with the package manager that owns this client.
/// The package's own scripts stop and restart this very service (deb prerm: systemctl
/// stop rustdesk), which would kill an installer started as our child halfway; so it
/// runs as a transient systemd unit of its own, and the package starts the new version.
#[cfg(target_os = "linux")]
fn update_new_version_linux(file_path: &PathBuf) -> ResultType<()> {
    let platform = crate::common::nemo_update_platform()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("this client was not installed from a package"))?;
    let file = file_path.to_string_lossy().to_string();
    let find = |name: &str| {
        ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"]
            .iter()
            .map(|d| format!("{d}{name}"))
            .find(|p| std::path::Path::new(p).exists())
    };
    let cmd: Vec<String> = match platform {
        "linux-deb" => vec![find("dpkg"), Some("-i".into()), Some("--force-confold".into()), Some(file)],
        "linux-rpm" => vec![find("rpm"), Some("-U".into()), Some("--replacepkgs".into()), Some(file)],
        "linux-arch" => vec![find("pacman"), Some("-U".into()), Some("--noconfirm".into()), Some(file)],
        other => bail!("no installer for platform {}", other),
    }
    .into_iter()
    .collect::<Option<Vec<_>>>()
    .ok_or_else(|| hbb_common::anyhow::anyhow!("package manager for {} not found", platform))?;
    let systemd_run = find("systemd-run")
        .ok_or_else(|| hbb_common::anyhow::anyhow!("systemd-run not found; cannot install outside this service"))?;
    let unit = format!("tbfdesk-update-{}", now_secs());
    log::info!("Installing the update with {:?} as transient unit {}", cmd, unit);
    let status = std::process::Command::new(systemd_run)
        .args(["--unit", &unit, "--collect", "--quiet", "--"])
        .args(&cmd)
        .status()?;
    if !status.success() {
        bail!("could not start the package installer: {}", status);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn update_new_version(update_msi: bool, version: &str, file_path: &PathBuf) {
    log::debug!(
        "New version is downloaded, update begin, update msi: {update_msi}, version: {version}, file: {:?}",
        file_path.to_str()
    );
    if let Some(p) = file_path.to_str() {
        if let Some(session_id) = crate::platform::get_current_process_session_id() {
            if update_msi {
                match crate::platform::update_me_msi(p, true) {
                    Ok(_) => {
                        log::debug!("New version \"{}\" updated.", version);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to install the new msi version  \"{}\": {}",
                            version,
                            e
                        );
                        std::fs::remove_file(&file_path).ok();
                    }
                }
            } else {
                let custom_client_staging_dir = if crate::is_custom_client() {
                    let custom_client_staging_dir =
                        crate::platform::get_custom_client_staging_dir();
                    if let Err(e) = crate::platform::handle_custom_client_staging_dir_before_update(
                        &custom_client_staging_dir,
                    ) {
                        log::error!(
                            "Failed to handle custom client staging dir before update: {}",
                            e
                        );
                        std::fs::remove_file(&file_path).ok();
                        return;
                    }
                    Some(custom_client_staging_dir)
                } else {
                    // Clean up any residual staging directory from previous custom client
                    let staging_dir = crate::platform::get_custom_client_staging_dir();
                    hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(
                        &staging_dir
                    ));
                    None
                };
                let update_launched = match crate::platform::launch_privileged_process(
                    session_id,
                    &format!("{} --update", p),
                ) {
                    Ok(h) => {
                        if h.is_null() {
                            log::error!("Failed to update to the new version: {}", version);
                            false
                        } else {
                            log::debug!("New version \"{}\" is launched.", version);
                            true
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to run the new version: {}", e);
                        false
                    }
                };
                if !update_launched {
                    if let Some(dir) = custom_client_staging_dir {
                        hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(
                            &dir
                        ));
                    }
                    std::fs::remove_file(&file_path).ok();
                }
            }
        } else {
            log::error!(
                "Failed to get the current process session id, Error {}",
                std::io::Error::last_os_error()
            );
            std::fs::remove_file(&file_path).ok();
        }
    } else {
        // unreachable!()
        log::error!(
            "Failed to convert the file path to string: {}",
            file_path.display()
        );
    }
}

// Auto-update: lowercase hex SHA-256 of a file, streamed so a large installer is
// not read into memory twice.
fn sha256_hex_of_file(path: &PathBuf) -> ResultType<String> {
    use hbb_common::sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

pub fn get_download_file_from_url(url: &str) -> Option<PathBuf> {
    let filename = url.split('/').last()?;
    Some(std::env::temp_dir().join(filename))
}
