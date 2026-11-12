#[cfg(any(target_os = "android", target_os = "ios"))]
use hbb_common::password_security;
use hbb_common::{
    allow_err,
    bytes::Bytes,
    config::{self, keys::*, Config, LocalConfig, PeerConfig, CONNECT_TIMEOUT, RENDEZVOUS_PORT},
    directories_next,
    futures::future::join_all,
    log,
    rendezvous_proto::*,
    tokio,
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::{
    sleep,
    tokio::{sync::mpsc, time},
};
use serde_derive::Serialize;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::process::Child;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::common::SOFTWARE_UPDATE_URL;
#[cfg(feature = "flutter")]
use crate::hbbs_http::account;
#[cfg(not(any(target_os = "ios")))]
use crate::ipc;

type Message = RendezvousMessage;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;

#[derive(Clone, Debug, Serialize)]
pub struct UiStatus {
    pub status_num: i32,
    // TBFDesk: also in the Flutter status (registration badge, FLUTTER-PORT A15).
    pub key_confirmed: bool,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub mouse_time: i64,
    #[cfg(not(feature = "flutter"))]
    pub id: String,
    #[cfg(feature = "flutter")]
    pub video_conn_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginDeviceInfo {
    pub os: String,
    pub r#type: String,
    pub name: String,
}

lazy_static::lazy_static! {
    static ref UI_STATUS : Arc<Mutex<UiStatus>> = Arc::new(Mutex::new(UiStatus{
        status_num: 0,
        key_confirmed: false,
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        mouse_time: 0,
        #[cfg(not(feature = "flutter"))]
        id: "".to_owned(),
        #[cfg(feature = "flutter")]
        video_conn_count: 0,
    }));
    static ref ASYNC_JOB_STATUS : Arc<Mutex<String>> = Default::default();
    static ref ASYNC_HTTP_STATUS : Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref TEMPORARY_PASSWD : Arc<Mutex<String>> = Arc::new(Mutex::new("".to_owned()));
    static ref IS_REMOTE_MODIFY_ENABLED_BY_CONTROL_PERMISSIONS : Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
lazy_static::lazy_static! {
    static ref OPTION_SYNCED: Arc<Mutex<bool>> = Default::default();
    static ref OPTIONS : Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(Config::get_options()));
    pub static ref SENDER : Mutex<mpsc::UnboundedSender<ipc::Data>> = Mutex::new(check_connect_status(true));
    static ref CHILDREN : Children = Default::default();
}

const NEMO_SERVER_CONFIG_KEYS: &[&str] = &[
    OPTION_CUSTOM_RENDEZVOUS_SERVER,
    OPTION_RELAY_SERVER,
    OPTION_API_SERVER,
    OPTION_KEY,
    "nemo-company-network-only",
];

fn nemo_is_server_config_key(key: &str) -> bool {
    NEMO_SERVER_CONFIG_KEYS.contains(&key)
}

fn nemo_preserve_locked_server_options(options: &mut HashMap<String, String>) {
    if !crate::nemo_exe_custom_server_configured() {
        return;
    }
    let current = Config::get_options();
    for key in NEMO_SERVER_CONFIG_KEYS {
        if let Some(value) = current.get(*key) {
            options.insert((*key).to_owned(), value.clone());
        } else {
            options.remove(*key);
        }
    }
}

fn nemo_restore_fixed_options(options: &mut HashMap<String, String>) {
    for (key, value) in config::OVERWRITE_SETTINGS.read().unwrap().iter() {
        options.insert(key.clone(), value.clone());
    }
    if nemo_management_locked() {
        for key in NEMO_MANAGEMENT_LOCKED_KEYS {
            let v = get_option(key);
            if v.is_empty() {
                options.remove(*key);
            } else {
                options.insert((*key).to_owned(), v);
            }
        }
    }
}

/// The management connection a policy was accepted over: the switch, the server and
/// the pinned management key.
const NEMO_MANAGEMENT_LOCKED_KEYS: &[&str] = &[
    "nemo-management-enabled",
    "nemo-management-server",
    "nemo-management-public-key",
];

/// Once this client has accepted a managed policy, the management dialog (both UIs) is
/// locked: unticking "enabled", blanking the server or swapping the key would stop the
/// server from ever changing the policy again (it holds regardless, see
/// nemo_management_client::restore_cached_policy). Importing a setup string stays
/// possible -- that is the operator re-pointing the machine, and it goes through
/// nemo_set_provisioned_options, which does not consult this.
fn nemo_management_locked() -> bool {
    !get_option("nemo-management-last-policy").trim().is_empty()
}

fn nemo_management_key_locked(key: &str) -> bool {
    NEMO_MANAGEMENT_LOCKED_KEYS.contains(&key) && nemo_management_locked()
}

#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    pub static ref IS_FILE_TRANSFER_ENABLED: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
}

const INIT_ASYNC_JOB_STATUS: &str = " ";

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_id() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::get_id();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_id();
}

#[inline]
pub fn goto_install() {
    allow_err!(crate::run_me(vec!["--install"]));
    std::process::exit(0);
}

#[inline]
pub fn install_me(_options: String, _path: String, _silent: bool, _debug: bool) {
    #[cfg(windows)]
    std::thread::spawn(move || {
        allow_err!(crate::platform::windows::install_me(
            &_options, _path, _silent, _debug
        ));
        std::process::exit(0);
    });
}

#[inline]
pub fn update_me(_path: String) {
    goto_install();
}

#[inline]
pub fn run_without_install() {
    crate::run_me(vec!["--noinstall"]).ok();
    std::process::exit(0);
}

#[inline]
pub fn show_run_without_install() -> bool {
    let mut it = std::env::args();
    if let Some(tmp) = it.next() {
        if crate::is_setup(&tmp) {
            return it.next() == None;
        }
    }
    false
}

#[inline]
pub fn get_license() -> String {
    #[cfg(windows)]
    if let Ok(lic) = crate::platform::windows::get_license_from_exe_name() {
        #[cfg(feature = "flutter")]
        return format!("Key: {}\nHost: {}\nAPI: {}", lic.key, lic.host, lic.api);
        // default license format is html formed (sciter)
        #[cfg(not(feature = "flutter"))]
        return format!(
            "<br /> Key: {} <br /> Host: {} API: {}",
            lic.key, lic.host, lic.api
        );
    }
    Default::default()
}

#[inline]
pub fn refresh_options() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        *OPTIONS.lock().unwrap() = Config::get_options();
    }
}

#[inline]
pub fn get_option<T: AsRef<str>>(key: T) -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let map = OPTIONS.lock().unwrap();
        if let Some(v) = map.get(key.as_ref()) {
            v.to_owned()
        } else {
            "".to_owned()
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        Config::get_option(key.as_ref())
    }
}

#[inline]
pub fn use_texture_render() -> bool {
    #[cfg(target_os = "android")]
    return false;
    #[cfg(target_os = "ios")]
    return false;

    #[cfg(target_os = "macos")]
    return cfg!(feature = "flutter")
        && LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) == "Y";

    #[cfg(target_os = "linux")]
    return cfg!(feature = "flutter")
        && LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) != "N";

    #[cfg(target_os = "windows")]
    {
        if !cfg!(feature = "flutter") {
            return false;
        }
        // https://learn.microsoft.com/en-us/windows/win32/sysinfo/targeting-your-application-at-windows-8-1
        #[cfg(debug_assertions)]
        let default_texture = true;
        #[cfg(not(debug_assertions))]
        let default_texture = crate::platform::is_win_10_or_greater();
        if default_texture {
            LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) != "N"
        } else {
            return LocalConfig::get_option(config::keys::OPTION_TEXTURE_RENDER) == "Y";
        }
    }
}

#[inline]
pub fn is_option_fixed(key: &str) -> bool {
    nemo_management_key_locked(key)
        || config::OVERWRITE_DISPLAY_SETTINGS
        .read()
        .unwrap()
        .contains_key(key)
        || config::OVERWRITE_LOCAL_SETTINGS
            .read()
            .unwrap()
            .contains_key(key)
        || config::OVERWRITE_SETTINGS.read().unwrap().contains_key(key)
}

#[inline]
pub fn get_local_option(key: String) -> String {
    crate::get_local_option(&key)
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_hard_option(key: String) -> String {
    config::HARD_SETTINGS
        .read()
        .unwrap()
        .get(&key)
        .cloned()
        .unwrap_or_default()
}

#[inline]
pub fn get_builtin_option(key: &str) -> String {
    crate::get_builtin_option(key)
}

#[inline]
pub fn set_local_option(key: String, value: String) {
    if is_option_fixed(&key) {
        return;
    }
    LocalConfig::set_option(key.clone(), value);
}

/// Resolve relative avatar path (e.g. "/avatar/xxx") to absolute URL
/// by prepending the API server address.
pub fn resolve_avatar_url(avatar: String) -> String {
    let avatar = avatar.trim().to_owned();
    if avatar.starts_with('/') {
        let api_server = get_api_server();
        if !api_server.is_empty() {
            return format!("{}{}", api_server.trim_end_matches('/'), avatar);
        }
    }
    avatar
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_local_flutter_option(key: String) -> String {
    LocalConfig::get_flutter_option(&key)
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn set_local_flutter_option(key: String, value: String) {
    LocalConfig::set_flutter_option(key, value);
}

#[cfg(feature = "flutter")]
#[inline]
pub fn get_kb_layout_type() -> String {
    LocalConfig::get_kb_layout_type()
}

#[cfg(feature = "flutter")]
#[inline]
pub fn set_kb_layout_type(kb_layout_type: String) {
    LocalConfig::set_kb_layout_type(kb_layout_type);
}

#[inline]
pub fn peer_has_password(id: String) -> bool {
    !PeerConfig::load(&id).password.is_empty()
}

#[inline]
pub fn forget_password(id: String) {
    let mut c = PeerConfig::load(&id);
    c.password.clear();
    c.store(&id);
}

#[inline]
pub fn get_peer_option(id: String, name: String) -> String {
    let c = PeerConfig::load(&id);
    c.options.get(&name).unwrap_or(&"".to_owned()).to_owned()
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_peer_flutter_option(id: String, name: String) -> String {
    let c = PeerConfig::load(&id);
    c.ui_flutter.get(&name).unwrap_or(&"".to_owned()).to_owned()
}

#[inline]
#[cfg(feature = "flutter")]
pub fn set_peer_flutter_option(id: String, name: String, value: String) {
    if is_option_fixed(&name) {
        return;
    }
    let mut c = PeerConfig::load(&id);
    if value.is_empty() {
        c.ui_flutter.remove(&name);
    } else {
        c.ui_flutter.insert(name, value);
    }
    c.store(&id);
}

#[inline]
pub fn set_peer_option(id: String, name: String, value: String) {
    if is_option_fixed(&name) {
        return;
    }
    let mut c = PeerConfig::load(&id);
    if value.is_empty() {
        c.options.remove(&name);
    } else {
        c.options.insert(name, value);
    }
    c.store(&id);
}

#[inline]
pub fn get_options() -> String {
    let options = {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            OPTIONS.lock().unwrap()
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            Config::get_options()
        }
    };
    let mut m = serde_json::Map::new();
    for (k, v) in options.iter() {
        m.insert(k.into(), v.to_owned().into());
    }
    serde_json::to_string(&m).unwrap_or_default()
}

#[inline]
pub fn test_if_valid_server(host: String, test_with_proxy: bool) -> String {
    hbb_common::socket_client::test_if_valid_server(&host, test_with_proxy)
}

#[inline]
#[cfg(feature = "flutter")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_sound_inputs() -> Vec<String> {
    let mut a = Vec::new();
    #[cfg(not(target_os = "linux"))]
    {
        fn get_sound_inputs_() -> Vec<String> {
            let mut out = Vec::new();
            use cpal::traits::{DeviceTrait, HostTrait};
            // Do not use `cpal::host_from_id(cpal::HostId::ScreenCaptureKit)` for feature = "screencapturekit"
            // Because we explicitly handle the "System Sound" device.
            let host = cpal::default_host();
            if let Ok(devices) = host.devices() {
                for device in devices {
                    if device.default_input_config().is_err() {
                        continue;
                    }
                    if let Ok(name) = device.name() {
                        out.push(name);
                    }
                }
            }
            out
        }

        let inputs = Arc::new(Mutex::new(Vec::new()));
        let cloned = inputs.clone();
        // can not call below in UI thread, because conflict with sciter sound com initialization
        std::thread::spawn(move || *cloned.lock().unwrap() = get_sound_inputs_())
            .join()
            .ok();
        for name in inputs.lock().unwrap().drain(..) {
            a.push(name);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let inputs: Vec<String> = crate::platform::linux::get_pa_sources()
            .drain(..)
            .map(|x| x.1)
            .collect();

        for name in inputs {
            a.push(name);
        }
    }
    a
}

#[inline]
pub fn set_options(mut m: HashMap<String, String>) {
    nemo_preserve_locked_server_options(&mut m);
    nemo_restore_fixed_options(&mut m);
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        *OPTIONS.lock().unwrap() = m.clone();
        ipc::set_options(m).ok();
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        // P-2: a device key riding in the map must stay wrapped at rest. `set_options`
        // REPLACES the stored map, so wrap it, then carry the stored (wrapped) form in the
        // map so the replace keeps it. `nemo_device_key_store` passes an already-wrapped
        // value through unchanged, so a settings round-trip does not double-encrypt it.
        if let Some(dk) = m.remove("nemo-device-key") {
            crate::common::nemo_device_key_store(&dk);
            let stored = Config::get_option("nemo-device-key");
            if !stored.is_empty() {
                m.insert("nemo-device-key".to_owned(), stored);
            }
        }
        Config::set_options(m);
    }
}

/// Provisioning write: the one path that may NOT be silently dropped.
///
/// `set_option` refuses two classes of key on purpose — those the server pushes as fixed
/// (`is_option_fixed`) and the four server keys a `host=…,key=…,relay=…` exe name owns
/// (`nemo_is_server_config_key`). Both guards exist so the SETTINGS DIALOG cannot drift
/// away from a managed value. Importing a setup string is the opposite situation: the
/// operator is deliberately re-pointing this machine, and a guard that silently discards
/// four of the six values leaves it half-provisioned — reported from the Windows test
/// workstation as "the setup string imports the ID server and nothing else".
///
/// So this writes through, in ONE batch: the whole set has to reach the service
/// together, because the service re-derives the locked keys from the config it is handed
/// (`nemo_preserve_locked_server_options`) and a key-by-key send lets it rebuild the old
/// server from a half-updated map in between. Values that `Config::set_option` would not
/// store at all are reported to the operator by the caller (`nemo_setup::apply_setup`);
/// nothing here pretends.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn nemo_set_provisioned_options(values: Vec<(String, String)>) {
    if values.is_empty() {
        return;
    }
    let mut options = OPTIONS.lock().unwrap();
    for (key, value) in values {
        if value.is_empty() {
            options.remove(&key);
        } else {
            options.insert(key, value);
        }
    }
    ipc::set_options(options.clone()).ok();
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn nemo_set_provisioned_options(values: Vec<(String, String)>) {
    for (key, value) in values {
        if key == "nemo-device-key" {
            // P-2: keep the provisioned device key wrapped at rest on Android.
            crate::common::nemo_device_key_store(&value);
        } else {
            Config::set_option(key, value);
        }
    }
}

#[inline]
pub fn set_option(key: String, value: String) {
    if is_option_fixed(&key) {
        return;
    }
    if crate::nemo_exe_custom_server_configured() && nemo_is_server_config_key(&key) {
        return;
    }
    if &key == "stop-service" {
        #[cfg(target_os = "macos")]
        {
            let is_stop = value == "Y";
            if is_stop && crate::platform::uninstall_service(true, false) {
                return;
            }
        }
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            if crate::platform::is_installed() {
                if value == "Y" {
                    if crate::platform::uninstall_service(true, false) {
                        return;
                    }
                } else {
                    if crate::platform::install_service() {
                        return;
                    }
                }
                return;
            }
        }
    } else if &key == "audio-input" {
        #[cfg(not(target_os = "ios"))]
        crate::audio_service::restart();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let mut options = OPTIONS.lock().unwrap();
        if value.is_empty() {
            options.remove(&key);
        } else {
            options.insert(key.clone(), value.clone());
        }
        ipc::set_options(options.clone()).ok();
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _nat = crate::CheckTestNatType::new();
        if key == "nemo-device-key" {
            // P-2: keep the device key wrapped at rest on Android (identity on iOS).
            crate::common::nemo_device_key_store(&value);
        } else {
            Config::set_option(key, value);
        }
    }
}

#[inline]
pub fn install_path() -> String {
    #[cfg(windows)]
    return crate::platform::windows::get_install_info().1;
    #[cfg(not(windows))]
    return "".to_owned();
}

#[inline]
pub fn install_options() -> String {
    #[cfg(windows)]
    return crate::platform::windows::get_install_options();
    #[cfg(not(windows))]
    return "{}".to_owned();
}

#[inline]
pub fn get_socks() -> Vec<String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let s = ipc::get_socks();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let s = Config::get_socks();
    match s {
        None => Vec::new(),
        Some(s) => {
            let mut v = Vec::new();
            v.push(s.proxy);
            v.push(s.username);
            v.push(s.password);
            v
        }
    }
}

#[inline]
pub fn set_socks(proxy: String, username: String, password: String) {
    let socks = config::Socks5Server {
        proxy,
        username,
        password,
    };
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    ipc::set_socks(socks).ok();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _nat = crate::CheckTestNatType::new();
        if socks.proxy.is_empty() {
            Config::set_socks(None);
        } else {
            Config::set_socks(Some(socks));
        }
        log::info!("socks updated");
    }
    #[cfg(target_os = "android")]
    {
        crate::RendezvousMediator::restart();
    }
}

#[inline]
#[cfg(feature = "flutter")]
pub fn get_proxy_status() -> bool {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_proxy_status();

    // Currently, only the desktop version has proxy settings.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return false;
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
pub fn is_installed() -> bool {
    crate::platform::is_installed()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[inline]
pub fn is_installed() -> bool {
    false
}

#[inline]
pub fn is_share_rdp() -> bool {
    #[cfg(windows)]
    return crate::platform::windows::is_share_rdp();
    #[cfg(not(windows))]
    return false;
}

#[inline]
pub fn set_share_rdp(_enable: bool) {
    #[cfg(windows)]
    crate::platform::windows::set_share_rdp(_enable);
}

#[inline]
pub fn is_installed_lower_version() -> bool {
    #[cfg(not(windows))]
    return false;
    #[cfg(windows)]
    {
        let b = crate::platform::windows::get_reg("BuildDate");
        return crate::BUILD_DATE.cmp(&b).is_gt();
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_mouse_time() -> f64 {
    UI_STATUS.lock().unwrap().mouse_time as f64
}

#[inline]
pub fn check_mouse_time() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let sender = SENDER.lock().unwrap();
        allow_err!(sender.send(ipc::Data::MouseMoveTime(0)));
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_connect_status() -> UiStatus {
    UI_STATUS.lock().unwrap().clone()
}

#[inline]
pub fn temporary_password() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return password_security::temporary_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return TEMPORARY_PASSWD.lock().unwrap().clone();
}

#[inline]
pub fn update_temporary_password() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    password_security::update_temporary_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    allow_err!(ipc::update_temporary_password());
}

#[inline]
pub fn is_permanent_password_set() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::has_permanent_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let daemon_is_set = ipc::is_permanent_password_set();
        // `daemon_is_set` is authoritative for the return value. Local storage is only used to
        // decide whether we should attempt a sync to clear stale user-side state.
        let local_storage_is_empty = if daemon_is_set {
            true
        } else {
            let (storage, _) = Config::get_local_permanent_password_storage_and_salt();
            storage.is_empty()
        };
        if daemon_is_set || !local_storage_is_empty {
            allow_err!(ipc::sync_permanent_password_storage_from_daemon());
        }
        daemon_is_set
    }
}

#[inline]
pub fn is_local_permanent_password_set() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::has_local_permanent_password();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        allow_err!(ipc::sync_permanent_password_storage_from_daemon());
        Config::has_local_permanent_password()
    }
}

pub fn set_permanent_password_with_result(password: String) -> bool {
    if config::Config::is_disable_change_permanent_password() {
        return false;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        config::Config::set_permanent_password(&password);
        return true;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        match crate::ipc::set_permanent_password_with_ack(password) {
            Ok(ok) => ok,
            Err(err) => {
                log::warn!("Failed to set permanent password via IPC: {err}");
                false
            }
        }
    }
}

#[inline]
pub fn get_peer(id: String) -> PeerConfig {
    PeerConfig::load(&id)
}

#[inline]
pub fn get_fav() -> Vec<String> {
    LocalConfig::get_fav()
}

#[inline]
pub fn store_fav(fav: Vec<String>) {
    LocalConfig::set_fav(fav);
}

#[inline]
pub fn is_process_trusted(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_process_trusted(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn is_can_screen_recording(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_can_screen_recording(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn is_installed_daemon(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_installed_daemon(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
#[cfg(feature = "flutter")]
pub fn is_can_input_monitoring(_prompt: bool) -> bool {
    #[cfg(target_os = "macos")]
    return crate::platform::macos::is_can_input_monitoring(_prompt);
    #[cfg(not(target_os = "macos"))]
    return true;
}

#[inline]
pub fn get_error() -> String {
    #[cfg(not(any(feature = "cli")))]
    #[cfg(target_os = "linux")]
    {
        let dtype = crate::platform::linux::get_display_server();
        if crate::platform::linux::DISPLAY_SERVER_WAYLAND == dtype {
            return crate::server::wayland::common_get_error();
        }
        if dtype != crate::platform::linux::DISPLAY_SERVER_X11 {
            return format!(
                "{} {}, {}",
                crate::client::translate("Unsupported display server".to_owned()),
                dtype,
                crate::client::translate("x11 expected".to_owned()),
            );
        }
    }
    return "".to_owned();
}

#[inline]
pub fn is_login_wayland() -> bool {
    #[cfg(target_os = "linux")]
    return crate::platform::linux::is_login_wayland();
    #[cfg(not(target_os = "linux"))]
    return false;
}

#[inline]
pub fn current_is_wayland() -> bool {
    #[cfg(target_os = "linux")]
    return crate::platform::linux::current_is_wayland();
    #[cfg(not(target_os = "linux"))]
    return false;
}

#[inline]
pub fn get_new_version() -> String {
    let v = crate::common::NEMO_UPDATE_VERSION.lock().unwrap().clone();
    if !v.is_empty() {
        return v;
    }
    (*SOFTWARE_UPDATE_URL
        .lock()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap_or(""))
    .to_string()
}

#[inline]
pub fn get_version() -> String {
    crate::VERSION.to_owned()
}

/// TBFDesk: build id baked by build.rs (git short hash + commit date, "+" when
/// the tree was dirty) and the UI ("Flutter" / "Sciter"), so a user can tell WHICH
/// build is running -- both UIs are built from the same commit.
#[inline]
pub fn get_build_id() -> String {
    format!("{} {}", env!("NEMO_BUILD_ID"), crate::common::nemo_ui_label())
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_app_name() -> String {
    crate::get_app_name()
}

#[cfg(windows)]
#[inline]
pub fn create_shortcut(_id: String) {
    crate::platform::windows::create_shortcut(&_id).ok();
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn discover() {
    std::thread::spawn(move || {
        allow_err!(crate::lan::discover());
    });
}

#[cfg(feature = "flutter")]
pub fn peer_to_map(id: String, p: PeerConfig) -> HashMap<&'static str, String> {
    use hbb_common::sodiumoxide::base64;
    HashMap::<&str, String>::from_iter([
        ("id", id),
        ("username", p.info.username.clone()),
        ("hostname", p.info.hostname.clone()),
        ("platform", p.info.platform.clone()),
        (
            "alias",
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ),
        (
            "hash",
            base64::encode(p.password, base64::Variant::Original),
        ),
    ])
}

#[cfg(feature = "flutter")]
pub fn peer_exists(id: &str) -> bool {
    PeerConfig::exists(id)
}

#[inline]
pub fn get_lan_peers() -> Vec<HashMap<&'static str, String>> {
    config::LanPeers::load()
        .peers
        .iter()
        .map(|peer| {
            HashMap::<&str, String>::from_iter([
                ("id", peer.id.clone()),
                ("username", peer.username.clone()),
                ("hostname", peer.hostname.clone()),
                ("platform", peer.platform.clone()),
            ])
        })
        .collect()
}

#[inline]
pub fn remove_discovered(id: String) {
    let mut peers = config::LanPeers::load().peers;
    peers.retain(|x| x.id != id);
    config::LanPeers::store(&peers);
}

#[inline]
pub fn get_uuid() -> String {
    crate::encode64(hbb_common::get_uuid())
}

#[inline]
pub fn get_init_async_job_status() -> String {
    INIT_ASYNC_JOB_STATUS.to_string()
}

#[inline]
pub fn reset_async_job_status() {
    *ASYNC_JOB_STATUS.lock().unwrap() = get_init_async_job_status();
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn change_id(id: String) {
    reset_async_job_status();
    let old_id = get_id();
    std::thread::spawn(move || {
        change_id_shared(id, old_id);
    });
}

#[inline]
pub fn http_request(url: String, method: String, body: Option<String>, header: String) {
    // Respond to concurrent requests for resources
    let current_request = ASYNC_HTTP_STATUS.clone();
    current_request
        .lock()
        .unwrap()
        .insert(url.clone(), " ".to_owned());
    std::thread::spawn(move || {
        let res = match crate::http_request_sync(url.clone(), method, body, header) {
            Err(err) => {
                log::error!("{}", err);
                err.to_string()
            }
            Ok(text) => text,
        };
        current_request.lock().unwrap().insert(url, res);
    });
}

#[inline]
pub fn get_async_http_status(url: String) -> Option<String> {
    match ASYNC_HTTP_STATUS.lock().unwrap().get(&url) {
        None => None,
        Some(_str) => Some(_str.to_string()),
    }
}

#[inline]
#[cfg(not(feature = "flutter"))]
pub fn post_request(url: String, body: String, header: String) {
    *ASYNC_JOB_STATUS.lock().unwrap() = " ".to_owned();
    std::thread::spawn(move || {
        *ASYNC_JOB_STATUS.lock().unwrap() = match crate::post_request_sync(url, body, &header) {
            Err(err) => err.to_string(),
            Ok(text) => text,
        };
    });
}

#[inline]
pub fn get_async_job_status() -> String {
    ASYNC_JOB_STATUS.lock().unwrap().clone()
}

#[inline]
pub fn get_langs() -> String {
    use serde_json::json;
    let mut x: Vec<(&str, String)> = crate::lang::LANGS
        .iter()
        .map(|a| (a.0, format!("{} ({})", a.1, a.0)))
        .collect();
    x.sort_by(|a, b| a.0.cmp(b.0));
    json!(x).to_string()
}

#[inline]
pub fn video_save_directory(root: bool) -> String {
    let appname = crate::get_app_name();
    // ui process can show it correctly Once vidoe process created it.
    let try_create = |path: &std::path::Path| {
        if !path.exists() {
            std::fs::create_dir_all(path).ok();
        }
        if path.exists() {
            path.to_string_lossy().to_string()
        } else {
            "".to_string()
        }
    };

    #[cfg(windows)]
    let program_data_dir = {
        let drive = std::env::var("SystemDrive").unwrap_or("C:".to_owned());
        std::path::PathBuf::from(format!("{drive}\\ProgramData\\{appname}\\recording",))
    };
    if root {
        // Currently, only installed windows run as root
        #[cfg(windows)]
        {
            return program_data_dir.to_string_lossy().to_string();
        }
    }
    // Get directory from config file otherwise --server will use the old value from global var.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let dir = LocalConfig::get_option_from_file(OPTION_VIDEO_SAVE_DIRECTORY);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let dir = LocalConfig::get_option(OPTION_VIDEO_SAVE_DIRECTORY);
    if !dir.is_empty() {
        return dir;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if let Ok(home) = config::APP_HOME_DIR.read() {
        let mut path = home.to_owned();
        path.push_str(format!("/{appname}/ScreenRecord").as_str());
        let dir = try_create(&std::path::Path::new(&path));
        if !dir.is_empty() {
            return dir;
        }
    }

    // TBFDesk, Windows: rank the default folders so a network share comes last.
    //   1. the user's Videos\{appname}, if it is on a local disk
    //   2. the machine-wide folder the installed service records incoming sessions to
    //   3. the other user folders on a local disk (Videos, Desktop, home)
    //   4. user folders on a network share (a Videos folder redirected to the roaming
    //      profile, e.g. \\dc\profiles$\<user>\Videos) - only if nothing else works
    #[cfg(windows)]
    {
        // (path, create it if missing)
        let mut user_dirs: Vec<(std::path::PathBuf, bool)> = Vec::new();
        if let Some(user) = directories_next::UserDirs::new() {
            if let Some(video_dir) = user.video_dir() {
                user_dirs.push((video_dir.join(&appname), true));
                user_dirs.push((video_dir.to_path_buf(), false));
            }
            if let Some(desktop_dir) = user.desktop_dir() {
                user_dirs.push((desktop_dir.to_path_buf(), false));
            }
            user_dirs.push((user.home_dir().to_path_buf(), false));
        }
        let pick = |path: &std::path::Path, create: bool| -> String {
            if create {
                try_create(path)
            } else if path.exists() {
                path.to_string_lossy().to_string()
            } else {
                "".to_string()
            }
        };
        let (network, local): (Vec<_>, Vec<_>) = user_dirs
            .into_iter()
            .partition(|(p, _)| crate::platform::windows::is_network_path(p));
        // 1. local Videos\{appname}
        if let Some((path, true)) = local.first() {
            let dir = try_create(path);
            if !dir.is_empty() {
                return dir;
            }
        }
        // 2. ProgramData
        let dir = try_create(&program_data_dir);
        if !dir.is_empty() {
            return dir;
        }
        // 3. other local user folders, then 4. user folders on a network share
        for (path, create) in local.iter().chain(network.iter()) {
            let dir = pick(path, *create);
            if !dir.is_empty() {
                return dir;
            }
        }
    }

    #[cfg(not(windows))]
    if let Some(user) = directories_next::UserDirs::new() {
        if let Some(video_dir) = user.video_dir() {
            let dir = try_create(&video_dir.join(&appname));
            if !dir.is_empty() {
                return dir;
            }
            if video_dir.exists() {
                return video_dir.to_string_lossy().to_string();
            }
        }
        if let Some(desktop_dir) = user.desktop_dir() {
            if desktop_dir.exists() {
                return desktop_dir.to_string_lossy().to_string();
            }
        }
        let home = user.home_dir();
        if home.exists() {
            return home.to_string_lossy().to_string();
        }
    }

    // same order as above
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Some(home) = crate::platform::get_active_user_home() {
        let name = if cfg!(target_os = "macos") {
            "Movies"
        } else {
            "Videos"
        };
        let video_dir = home.join(name);
        let dir = try_create(&video_dir.join(&appname));
        if !dir.is_empty() {
            return dir;
        }
        if video_dir.exists() {
            return video_dir.to_string_lossy().to_string();
        }
        let desktop_dir = home.join("Desktop");
        if desktop_dir.exists() {
            return desktop_dir.to_string_lossy().to_string();
        }
        if home.exists() {
            return home.to_string_lossy().to_string();
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let dir = try_create(&parent.join("videos"));
            if !dir.is_empty() {
                return dir;
            }
            // basically exist
            return parent.to_string_lossy().to_string();
        }
    }
    Default::default()
}

#[inline]
pub fn get_api_server() -> String {
    crate::get_api_server(
        get_option("api-server"),
        get_option("custom-rendezvous-server"),
    )
}

#[inline]
pub fn has_hwcodec() -> bool {
    // Has real hardware codec using gpu
    (cfg!(feature = "hwcodec") && cfg!(not(target_os = "ios"))) || cfg!(feature = "mediacodec")
}

#[inline]
pub fn has_vram() -> bool {
    cfg!(feature = "vram")
}

#[cfg(feature = "flutter")]
#[inline]
pub fn supported_hwdecodings() -> (bool, bool) {
    let decoding =
        scrap::codec::Decoder::supported_decodings(None, use_texture_render(), None, &vec![]);
    #[allow(unused_mut)]
    let (mut h264, mut h265) = (decoding.ability_h264 > 0, decoding.ability_h265 > 0);
    #[cfg(feature = "vram")]
    {
        // supported_decodings check runtime luid
        let vram = scrap::vram::VRamDecoder::possible_available_without_check();
        if vram.0 {
            h264 = true;
        }
        if vram.1 {
            h265 = true;
        }
    }
    (h264, h265)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
pub fn is_root() -> bool {
    crate::platform::is_root()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[inline]
pub fn is_root() -> bool {
    false
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn check_super_user_permission() -> bool {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return crate::platform::check_super_user_permission().unwrap_or(false);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return true;
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn check_zombie() {
    let mut deads = Vec::new();
    loop {
        let mut lock = CHILDREN.lock().unwrap();
        let mut n = 0;
        for (id, c) in lock.1.iter_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                deads.push(id.clone());
                n += 1;
            }
        }
        for ref id in deads.drain(..) {
            lock.1.remove(id);
        }
        if n > 0 {
            lock.0 = true;
        }
        drop(lock);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios", feature = "flutter")))]
/// Returns false when a session of this type to this peer is already open: nothing is
/// started, its window is brought forward where the platform allows it, and the caller
/// says so (it used to return silently, and a second click looked broken). Sessions to
/// other peers are unaffected.
pub fn new_remote(id: String, remote_type: String, force_relay: bool) -> bool {
    let mut lock = CHILDREN.lock().unwrap();
    let mut args = vec![format!("--{}", remote_type), id.clone()];
    if force_relay {
        args.push("".to_string()); // password
        args.push("--relay".to_string());
    }
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                #[cfg(windows)]
                crate::platform::windows::raise_process_windows(c.id());
                return false;
            }
        }
    }
    match crate::run_me(args) {
        Ok(child) => {
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
    true
}

// Make sure `SENDER` is inited here.
#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn start_option_status_sync() {
    let _sender = SENDER.lock().unwrap();
}

// not call directly
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn check_connect_status(reconnect: bool) -> mpsc::UnboundedSender<ipc::Data> {
    let (tx, rx) = mpsc::unbounded_channel::<ipc::Data>();
    std::thread::spawn(move || check_connect_status_(reconnect, rx));
    tx
}

#[cfg(feature = "flutter")]
pub fn account_auth(op: String, id: String, uuid: String, remember_me: bool) {
    account::OidcSession::account_auth(get_api_server(), op, id, uuid, remember_me);
}

#[cfg(feature = "flutter")]
pub fn account_auth_cancel() {
    account::OidcSession::auth_cancel();
}

#[cfg(feature = "flutter")]
pub fn account_auth_result() -> String {
    serde_json::to_string(&account::OidcSession::get_result()).unwrap_or_default()
}

#[cfg(feature = "flutter")]
pub fn set_user_default_option(key: String, value: String) {
    use hbb_common::config::UserDefaultConfig;
    UserDefaultConfig::load().set(key, value);
}

#[cfg(feature = "flutter")]
pub fn get_user_default_option(key: String) -> String {
    use hbb_common::config::UserDefaultConfig;
    UserDefaultConfig::load().get(&key)
}

pub fn get_fingerprint() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if Config::get_key_confirmed() {
        return crate::common::pk_to_fingerprint(Config::get_key_pair().1);
    } else {
        return "".to_owned();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_fingerprint();
}

#[inline]
pub fn get_login_device_info() -> LoginDeviceInfo {
    LoginDeviceInfo {
        // std::env::consts::OS is better than whoami::platform() here.
        os: std::env::consts::OS.to_owned(),
        r#type: "client".to_owned(),
        name: crate::common::hostname(),
    }
}

#[inline]
pub fn get_login_device_info_json() -> String {
    serde_json::to_string(&get_login_device_info()).unwrap_or("{}".to_string())
}

// notice: avoiding create ipc connection repeatedly,
// because windows named pipe has serious memory leak issue.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn check_connect_status_(reconnect: bool, rx: mpsc::UnboundedReceiver<ipc::Data>) {
    let mut key_confirmed = false;
    let mut rx = rx;
    let mut mouse_time = 0;
    #[cfg(feature = "flutter")]
    let mut video_conn_count = 0;
    #[cfg(not(feature = "flutter"))]
    let mut id = "".to_owned();
    let is_cm = crate::common::is_cm();

    loop {
        if let Ok(mut c) = ipc::connect(1000, "").await {
            let mut timer = crate::rustdesk_interval(time::interval(time::Duration::from_secs(1)));
            loop {
                tokio::select! {
                    res = c.next() => {
                        match res {
                            Err(err) => {
                                log::error!("ipc connection closed: {}", err);
                                if is_cm {
                                    crate::ui_cm_interface::quit_cm();
                                }
                                break;
                            }
                            #[cfg(not(any(target_os = "android", target_os = "ios")))]
                            Ok(Some(ipc::Data::MouseMoveTime(v))) => {
                                mouse_time = v;
                                UI_STATUS.lock().unwrap().mouse_time = v;
                            }
                            Ok(Some(ipc::Data::Options(Some(v)))) => {
                                *OPTIONS.lock().unwrap() = v;
                                *OPTION_SYNCED.lock().unwrap() = true;
                            }
                            Ok(Some(ipc::Data::Config((name, Some(value))))) => {
                                if name == "id" {
                                    #[cfg(not(feature = "flutter"))]
                                    {
                                        id = value;
                                    }
                                } else if name == "temporary-password" {
                                    *TEMPORARY_PASSWD.lock().unwrap() = value;
                                }
                            }
                            #[cfg(feature = "flutter")]
                            Ok(Some(ipc::Data::VideoConnCount(Some(n)))) => {
                                video_conn_count = n;
                            }
                            Ok(Some(ipc::Data::OnlineStatus(Some((mut x, _c))))) => {
                                if x > 0 {
                                    x = 1
                                }
                                key_confirmed = _c;
                                *UI_STATUS.lock().unwrap() = UiStatus {
                                    status_num: x as _,
                                    key_confirmed: _c,
                                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                                    mouse_time,
                                    #[cfg(not(feature = "flutter"))]
                                    id: id.clone(),
                                    #[cfg(feature = "flutter")]
                                    video_conn_count,
                                };
                            }
                            Ok(Some(ipc::Data::ControlPermissionsRemoteModify(v))) => {
                                *IS_REMOTE_MODIFY_ENABLED_BY_CONTROL_PERMISSIONS.lock().unwrap() = v;
                            }
                            #[cfg(target_os = "windows")]
                            Ok(Some(ipc::Data::FileTransferEnabledState(v))) => {
                                if let Some(enabled) = v {
                                    let mut lock = IS_FILE_TRANSFER_ENABLED.lock().unwrap();
                                    if *lock != v {
                                        clipboard::ContextSend::enable(enabled);
                                        *lock = v;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(data) = rx.recv() => {
                        allow_err!(c.send(&data).await);
                    }
                    _ = timer.tick() => {
                        c.send(&ipc::Data::OnlineStatus(None)).await.ok();
                        c.send(&ipc::Data::Options(None)).await.ok();
                        c.send(&ipc::Data::Config(("id".to_owned(), None))).await.ok();
                        c.send(&ipc::Data::Config(("temporary-password".to_owned(), None))).await.ok();
                        #[cfg(feature = "flutter")]
                        c.send(&ipc::Data::VideoConnCount(None)).await.ok();
                        c.send(&ipc::Data::ControlPermissionsRemoteModify(None)).await.ok();
                        #[cfg(target_os = "windows")]
                        c.send(&ipc::Data::FileTransferEnabledState(None)).await.ok();
                    }
                }
            }
        }
        if !reconnect {
            OPTIONS
                .lock()
                .unwrap()
                .insert("ipc-closed".to_owned(), "Y".to_owned());
            break;
        }
        *UI_STATUS.lock().unwrap() = UiStatus {
            status_num: -1,
            key_confirmed,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            mouse_time,
            #[cfg(not(feature = "flutter"))]
            id: id.clone(),
            #[cfg(feature = "flutter")]
            video_conn_count,
        };
        sleep(1.).await;
    }
}

#[allow(dead_code)]
pub fn option_synced() -> bool {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        OPTION_SYNCED.lock().unwrap().clone()
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        true
    }
}

#[cfg(any(target_os = "android", feature = "flutter"))]
#[cfg(not(any(target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub(crate) async fn send_to_cm(data: &ipc::Data) {
    if let Ok(mut c) = ipc::connect(1000, "_cm").await {
        c.send(data).await.ok();
    }
}

const INVALID_FORMAT: &'static str = "Invalid format";
const UNKNOWN_ERROR: &'static str = "Unknown error";

#[inline]
#[tokio::main(flavor = "current_thread")]
pub async fn change_id_shared(id: String, old_id: String) -> String {
    let res = change_id_shared_(id, old_id).await.to_owned();
    *ASYNC_JOB_STATUS.lock().unwrap() = res.clone();
    res
}

pub async fn change_id_shared_(id: String, old_id: String) -> &'static str {
    if !hbb_common::is_valid_custom_id(&id) {
        log::debug!(
            "debugging invalid id: \"{id}\", len: {}, base64: \"{}\"",
            id.len(),
            crate::encode64(&id)
        );
        let bom = id.trim_start_matches('\u{FEFF}');
        log::debug!("bom: {}", hbb_common::is_valid_custom_id(&bom));
        return INVALID_FORMAT;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let uuid = Bytes::from(
        hbb_common::machine_uid::get()
            .unwrap_or("".to_owned())
            .as_bytes()
            .to_vec(),
    );
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let uuid = Bytes::from(hbb_common::get_uuid());

    if uuid.is_empty() {
        log::error!("Failed to change id, uuid is_empty");
        return UNKNOWN_ERROR;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let rendezvous_servers = crate::ipc::get_rendezvous_servers(1_000).await;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let rendezvous_servers = Config::get_rendezvous_servers();

    let mut futs = Vec::new();
    let err: Arc<Mutex<&str>> = Default::default();
    for rendezvous_server in rendezvous_servers {
        let err = err.clone();
        let id = id.to_owned();
        let uuid = uuid.clone();
        let old_id = old_id.clone();
        futs.push(tokio::spawn(async move {
            let tmp = check_id(rendezvous_server, old_id, id, uuid).await;
            if !tmp.is_empty() {
                *err.lock().unwrap() = tmp;
            }
        }));
    }
    join_all(futs).await;
    let err = *err.lock().unwrap();
    if err.is_empty() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        crate::ipc::set_config_async("id", id.to_owned()).await.ok();
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            Config::set_key_confirmed(false);
            Config::set_id(&id);
        }
    }
    err
}

async fn check_id(
    rendezvous_server: String,
    old_id: String,
    id: String,
    uuid: Bytes,
) -> &'static str {
    if let Ok(mut socket) = hbb_common::socket_client::connect_tcp(
        crate::check_port(rendezvous_server, RENDEZVOUS_PORT),
        CONNECT_TIMEOUT,
    )
    .await
    {
        let mut msg_out = Message::new();
        msg_out.set_register_pk(RegisterPk {
            old_id,
            id,
            uuid,
            ..Default::default()
        });
        let mut ok = false;
        if socket.send(&msg_out).await.is_ok() {
            if let Some(msg_in) =
                crate::common::get_next_nonkeyexchange_msg(&mut socket, None).await
            {
                match msg_in.union {
                    Some(rendezvous_message::Union::RegisterPkResponse(rpr)) => {
                        match rpr.result.enum_value() {
                            Ok(register_pk_response::Result::OK) => {
                                ok = true;
                            }
                            Ok(register_pk_response::Result::ID_EXISTS) => {
                                return "Not available";
                            }
                            Ok(register_pk_response::Result::TOO_FREQUENT) => {
                                return "Too frequent";
                            }
                            Ok(register_pk_response::Result::NOT_SUPPORT) => {
                                return "server_not_support";
                            }
                            Ok(register_pk_response::Result::SERVER_ERROR) => {
                                return "Server error";
                            }
                            Ok(register_pk_response::Result::INVALID_ID_FORMAT) => {
                                return INVALID_FORMAT;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        if !ok {
            return UNKNOWN_ERROR;
        }
    } else {
        return "Failed to connect to rendezvous server";
    }
    ""
}

// if it's relay id, return id processed, otherwise return original id
pub fn handle_relay_id(id: &str) -> &str {
    if id.ends_with(r"\r") || id.ends_with(r"/r") {
        &id[0..id.len() - 2]
    } else {
        id
    }
}

pub fn support_remove_wallpaper() -> bool {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    return crate::platform::WallPaperRemover::support();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    return false;
}

pub fn has_valid_2fa() -> bool {
    let raw = get_option("2fa");
    crate::auth_2fa::get_2fa(Some(raw)).is_some()
}

pub fn generate2fa() -> String {
    crate::auth_2fa::generate2fa()
}

pub fn verify2fa(code: String) -> bool {
    let res = crate::auth_2fa::verify2fa(code);
    if res {
        refresh_options();
    }
    res
}

pub fn has_valid_bot() -> bool {
    crate::auth_2fa::TelegramBot::get().map_or(false, |bot| bot.is_some())
}

pub fn verify_bot(token: String) -> String {
    match crate::auth_2fa::get_chatid_telegram(&token) {
        Err(err) => err.to_string(),
        Ok(None) => {
            "To activate the bot, simply send a message beginning with a forward slash (\"/\") like \"/hello\" to its chat.".to_owned()
        }
        _ => "".to_owned(),
    }
}

pub fn check_hwcodec() {
    #[cfg(feature = "hwcodec")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        use std::sync::Once;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| {
            if crate::platform::is_installed() {
                ipc::notify_server_to_check_hwcodec().ok();
                ipc::client_get_hwcodec_config_thread(3);
            } else {
                scrap::hwcodec::start_check_process();
            }
        })
    }
}

#[cfg(feature = "flutter")]
pub fn get_unlock_pin() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return String::default();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_unlock_pin();
}

#[cfg(feature = "flutter")]
pub fn set_unlock_pin(pin: String) -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return String::default();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    match ipc::set_unlock_pin(pin, true) {
        Ok(_) => String::default(),
        Err(err) => err.to_string(),
    }
}

#[cfg(feature = "flutter")]
pub fn get_trusted_devices() -> String {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    return Config::get_trusted_devices_json();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    return ipc::get_trusted_devices();
}

#[cfg(feature = "flutter")]
pub fn remove_trusted_devices(json: &str) {
    let hwids = serde_json::from_str::<Vec<Bytes>>(json).unwrap_or_default();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Config::remove_trusted_devices(&hwids);
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    ipc::remove_trusted_devices(hwids);
}

#[cfg(feature = "flutter")]
pub fn clear_trusted_devices() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Config::clear_trusted_devices();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    ipc::clear_trusted_devices();
}

#[cfg(feature = "flutter")]
pub fn max_encrypt_len() -> usize {
    hbb_common::config::ENCRYPT_MAX_LEN
}

pub fn is_remote_modify_enabled_by_control_permissions() -> Option<bool> {
    *IS_REMOTE_MODIFY_ENABLED_BY_CONTROL_PERMISSIONS
        .lock()
        .unwrap()
}

// Options that script may write but must never read back. Keep this list tight and
// keep the reason with it: an entry here is a secret whose value the GUI has no
// legitimate use for. `nemo-device-key` is the Layer 1 private key; the import dialog
// writes it and `nemo_device_key_present()` reports whether one exists, which is all
// the interface needs.
pub const NEMO_SCRIPT_SECRET_OPTIONS: &[&str] = &["nemo-device-key"];

/// Server/security STATE the policy client maintains between polls. Unlike the
/// secrets above, script CAN read these (they are not filtered by get_option/
/// get_options), so a settings dialog captures a real snapshot when it opens --
/// and the snapshot goes stale the moment a poll updates the live value while the
/// dialog is still open (a session cut is acked, a policy is accepted, a peer key
/// pins, a peer is blocked). Round-tripping that snapshot on Save would revert the
/// live value, undoing the cut or re-arming a downgrade/replay guard. These are
/// always overwritten with the CURRENT live value before saving, discarding
/// whatever the dialog happened to be holding.
pub const NEMO_SCRIPT_MANAGED_OPTIONS: &[&str] = &[
    "nemo-terminate-acked",
    "nemo-policy-issued-ts",
    "nemo-policy-seal-seen",
    "nemo-blocked-ids",
    "nemo-peer-keys",
    "nemo-require-encrypted-session",
];

#[inline]
pub fn nemo_is_script_secret(key: &str) -> bool {
    NEMO_SCRIPT_SECRET_OPTIONS.contains(&key.trim())
}

/// A map coming back from script cannot carry the secret keys, because script was never
/// shown them. Re-insert each one from the live config unless script supplied a value
/// itself (the import dialog does, through set_option, not through here).
pub fn nemo_reinject_script_secrets(
    m: &mut HashMap<String, String>,
    live: impl Fn(&str) -> String,
) {
    for key in NEMO_SCRIPT_SECRET_OPTIONS {
        if !m.contains_key(*key) {
            let v = live(key);
            if !v.is_empty() {
                m.insert((*key).to_owned(), v);
            }
        }
    }
}

/// Unlike nemo_reinject_script_secrets (fill ONLY if absent), this always takes the
/// live value for NEMO_SCRIPT_MANAGED_OPTIONS, overwriting anything script sent --
/// that stale snapshot is exactly the bug. An empty live value clears the key, same
/// as any other option a user has never set.
pub fn nemo_restore_managed_state(m: &mut HashMap<String, String>, live: impl Fn(&str) -> String) {
    for key in NEMO_SCRIPT_MANAGED_OPTIONS {
        let v = live(key);
        if v.is_empty() {
            m.remove(*key);
        } else {
            m.insert((*key).to_owned(), v);
        }
    }
}

#[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
mod nemo_management_lock_tests {
    use super::*;

    #[test]
    fn management_dialog_is_locked_once_a_policy_was_accepted() {
        let saved = OPTIONS.lock().unwrap().clone();
        let set = |k: &str, v: &str| {
            OPTIONS.lock().unwrap().insert(k.to_owned(), v.to_owned());
        };
        set("nemo-management-enabled", "Y");
        set("nemo-management-server", "https://mgmt.example:21121");
        set("nemo-management-public-key", "pk");
        OPTIONS.lock().unwrap().remove("nemo-management-last-policy");
        assert!(!is_option_fixed("nemo-management-enabled"), "unmanaged: editable");

        set("nemo-management-last-policy", r#"{"allow_user_override":false,"options":{}}"#);
        for k in NEMO_MANAGEMENT_LOCKED_KEYS {
            assert!(is_option_fixed(k), "{k} must be fixed once a policy was accepted");
        }
        assert!(!is_option_fixed("enable-audio"), "other keys are unaffected");
        // A bulk save from a dialog that unticked management and swapped the server
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("nemo-management-enabled".into(), "".into());
        m.insert("nemo-management-server".into(), "https://elsewhere".into());
        m.remove("nemo-management-public-key");
        nemo_restore_fixed_options(&mut m);
        assert_eq!(m.get("nemo-management-enabled").map(String::as_str), Some("Y"));
        assert_eq!(
            m.get("nemo-management-server").map(String::as_str),
            Some("https://mgmt.example:21121")
        );
        assert_eq!(m.get("nemo-management-public-key").map(String::as_str), Some("pk"));

        *OPTIONS.lock().unwrap() = saved;
    }
}

#[cfg(test)]
mod nemo_script_secret_tests {
    use super::*;

    #[test]
    fn managed_state_always_takes_the_live_value_over_a_stale_snapshot() {
        // The dialog opened with terminate-acked=100, then a cut bumped it to 200
        // while the dialog was still open; Save must not revert it to 100.
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("nemo-terminate-acked".into(), "100".into());
        m.insert("codec-preference".into(), "vp9".into());
        nemo_restore_managed_state(&mut m, |k| {
            if k == "nemo-terminate-acked" {
                "200".into()
            } else {
                String::new()
            }
        });
        assert_eq!(
            m.get("nemo-terminate-acked").map(String::as_str),
            Some("200")
        );
        assert_eq!(m.get("codec-preference").map(String::as_str), Some("vp9"));
    }

    #[test]
    fn managed_state_absent_live_clears_the_stale_snapshot() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("nemo-blocked-ids".into(), "old-blocked-list".into());
        nemo_restore_managed_state(&mut m, |_| String::new());
        assert!(!m.contains_key("nemo-blocked-ids"));
    }

    #[test]
    fn a_round_tripped_map_keeps_the_device_key() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("codec-preference".into(), "vp9".into());
        nemo_reinject_script_secrets(&mut m, |k| {
            if k == "nemo-device-key" {
                "live-secret".into()
            } else {
                String::new()
            }
        });
        assert_eq!(
            m.get("nemo-device-key").map(String::as_str),
            Some("live-secret")
        );
        assert_eq!(m.get("codec-preference").map(String::as_str), Some("vp9"));
    }

    #[test]
    fn a_value_script_did_supply_is_left_alone_and_an_empty_live_value_is_not_inserted() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("nemo-device-key".into(), "from-script".into());
        nemo_reinject_script_secrets(&mut m, |_| "live-secret".into());
        assert_eq!(
            m.get("nemo-device-key").map(String::as_str),
            Some("from-script")
        );
        let mut empty: HashMap<String, String> = HashMap::new();
        nemo_reinject_script_secrets(&mut empty, |_| String::new());
        assert!(!empty.contains_key("nemo-device-key"));
    }
}

/// `get_option` for a UI front end (Sciter script, Flutter Dart): the secret options
/// read back as empty. Writing them stays possible through `set_option`.
pub fn get_option_for_ui(key: String) -> String {
    if nemo_is_script_secret(&key) {
        return "".to_owned();
    }
    get_option(key)
}

/// `get_options` for a UI front end: the whole map minus the secret options. Filtering
/// only the single-key getter would leave the key readable through this one.
pub fn get_options_for_ui() -> String {
    let mut m: HashMap<String, String> = serde_json::from_str(&get_options()).unwrap_or_default();
    m.retain(|k, _| !nemo_is_script_secret(k));
    serde_json::to_string(&m).unwrap_or_default()
}

/// `set_options` for a map that came back from a UI front end. The UI never saw the
/// secret keys, and `set_options` REPLACES the whole map, so absence is not a request
/// to delete: put the live secret back. Server-managed state always takes the live
/// value, never the UI's possibly stale snapshot.
pub fn set_options_from_ui(mut m: HashMap<String, String>) {
    nemo_reinject_script_secrets(&mut m, |k| get_option(k.to_owned()));
    nemo_restore_managed_state(&mut m, |k| get_option(k.to_owned()));
    set_options(m);
}

/// Update banner state for a UI front end: `{"version": <new version or "">, "auto": bool}`.
/// `auto` = this client installs updates itself (policy `nemo-auto-update`, a platform the
/// updater supports, and an installed client); otherwise the administrator must.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn nemo_update_state() -> String {
    let auto = Config::get_option("nemo-auto-update") == "Y"
        && crate::common::nemo_update_platform().is_some()
        && crate::platform::is_installed();
    serde_json::json!({ "version": get_new_version(), "auto": auto }).to_string()
}

/// "Install now": ask the service's updater (over IPC) to install the pending version.
/// It downloads, verifies the SHA-256 and installs within a minute, never during a
/// session. This is the ONLY install path a UI may trigger.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn nemo_update_now() {
    let v = get_new_version();
    if v.is_empty() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::ipc::set_option(crate::updater::OPTION_UPDATE_REQUEST, &format!("{v}:{now}"));
}

/// The update prompt's answer (`now` / `postpone`) for `version`, sent to the service's
/// updater. No answer at all means "install when the countdown ends".
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn nemo_update_answer(choice: &str, version: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::ipc::set_option(
        crate::updater::OPTION_UPDATE_DECISION,
        &format!("{choice}:{version}:{now}"),
    );
}

// ---- TBFDesk handlers shared by the Sciter (src/ui.rs) and Flutter (src/flutter_ffi.rs) UIs ----

/// S-B (P0): device-key fields to add to an /api/ab/get request so the server can seal
/// the address book to this client. JSON object string
/// {"sealed":"v1","id":..,"device_key_pub":..,"device_key_sig":..}, or "{}" when no
/// device key is imported (the server then returns the plaintext list).
pub fn nemo_ab_seal_fields(id: String) -> String {
    let (pubk, sig) = crate::common::nemo_device_sign("nemo-ab", &id);
    if pubk.is_empty() {
        return "{}".to_owned();
    }
    serde_json::json!({
        "sealed": "v1",
        "id": id,
        "device_key_pub": pubk,
        "device_key_sig": sig,
    })
    .to_string()
}

/// S-B (P0) / A6: unseal an address book the server SIGN-then-SEALED to our device key,
/// verifying the inner server signature. Verified plaintext JSON, or "" on any failure.
pub fn nemo_unseal_ab(sealed_b64: String) -> String {
    match crate::common::nemo_open_sealed_signed(&sealed_b64) {
        Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        None => String::new(),
    }
}

lazy_static::lazy_static! {
    /// What the last imported setup string changed, for the import dialog to show.
    static ref NEMO_SETUP_SUMMARY: Mutex<String> = Default::default();
}

/// Apply a first-run setup string. "" on success, otherwise the reason. On success the
/// summary of what changed is kept for `nemo_setup_summary`.
pub fn nemo_apply_setup_string(text: String) -> String {
    match crate::nemo_setup::parse_setup(&text) {
        Ok(bundle) => {
            let outcome = crate::nemo_setup::apply_setup(&bundle);
            // apply_setup writes through Config::set_option (this GUI process only).
            // Re-send each applied value to the service over IPC so the running
            // rendezvous/poll adopts the new server, key and device key immediately —
            // without this, a GUI import changes nothing for the live client until a
            // restart (the service keeps its own config). Read the freshly written
            // value from Config, not ui_interface's OPTIONS cache, which apply_setup
            // did not touch.
            //
            // NOT through set_option: that one returns silently for the four keys a
            // `host=…,key=…,relay=…` exe name owns, and for anything the server
            // pushes as a fixed default — so on a locked-exe client it dropped
            // exactly `custom-rendezvous-server`, `relay-server`, `api-server` and
            // `key`, i.e. the whole point of the bundle. An import is a deliberate
            // re-provisioning by the operator and therefore writes through.
            let mut provisioned = Vec::new();
            for &k in crate::nemo_setup::APPLIED_OPTION_KEYS {
                let v = hbb_common::config::Config::get_option(k);
                if !v.trim().is_empty() {
                    provisioned.push((k.to_string(), v));
                }
            }
            // The override marker travels with them, so the service's own
            // set_options does not put the exe-name server back.
            let marker = crate::nemo_setup::OPTION_SETUP_OVERRIDES_EXE;
            let marker_value = hbb_common::config::Config::get_option(marker);
            if !marker_value.is_empty() {
                provisioned.push((marker.to_string(), marker_value));
            }
            crate::ui_interface::nemo_set_provisioned_options(provisioned);
            let mut summary = outcome.applied.clone();
            if !outcome.refused.is_empty() {
                summary.push(String::new());
                summary.push(crate::nemo_setup::REFUSED_HEADING.to_owned());
                summary.extend(outcome.refused.clone());
            }
            *NEMO_SETUP_SUMMARY.lock().unwrap() = summary.join("\n");
            String::new()
        }
        Err(err) => err.to_string(),
    }
}

/// What the last successful import changed, newline separated. Only knowable at the
/// moment of the write ("ID server: x (was y)"), so it is kept, not derived.
pub fn nemo_setup_summary() -> String {
    NEMO_SETUP_SUMMARY.lock().unwrap().clone()
}

/// The api-server as the CONFIG has it (falls back to the ID server), not as the UI's
/// option cache has it: on a machine provisioned in this session the cache can still be
/// empty and the login gate would ask for an address the setup string just supplied.
pub fn nemo_configured_api_server() -> String {
    let api = hbb_common::config::Config::get_option("api-server");
    if !api.trim().is_empty() {
        return api.trim().to_owned();
    }
    hbb_common::config::Config::get_option("custom-rendezvous-server")
        .trim()
        .to_owned()
}

/// A short, translated knock status line for `id` ("Knock :62201 · own key"), or "" when
/// this client would not knock before dialling it.
// translate_locale, not translate: translate is compiled out on Android/iOS. Same result on
// desktop -- the fork's "lang" option is never empty (default "de"), so the system locale
// argument is never consulted.
pub fn nemo_knock_hint(id: String) -> String {
    match crate::nemo_direct::knock_port_for(&id) {
        None => String::new(),
        Some(port) => {
            let which = if crate::nemo_direct::has_peer_knock_key(&id) {
                crate::lang::translate_locale("own key".to_owned(), "")
            } else {
                crate::lang::translate_locale("fleet key".to_owned(), "")
            };
            // e.g. "Knock :62201 · own key"
            format!(
                "{} :{} \u{00B7} {}",
                crate::lang::translate_locale("Knock".to_owned(), ""),
                port,
                which
            )
        }
    }
}

/// "Reset preferences" on a peer: view style, quality, keyboard mode, toggles, display
/// mode, relay/direct preferences, window sizes back to defaults. Kept: the remembered
/// password, the alias, the RDP / OS credentials and the peer info. false when there was
/// nothing stored for `id`.
pub fn nemo_reset_peer_prefs(id: String) -> bool {
    let id = id.trim().to_owned();
    if id.is_empty() || !hbb_common::config::PeerConfig::exists(&id) {
        return false;
    }
    let old = hbb_common::config::PeerConfig::load(&id);
    let mut fresh = hbb_common::config::PeerConfig::default();
    fresh.password = old.password.clone();
    fresh.info = old.info.clone();
    for key in [
        "alias",
        "rdp_port",
        "rdp_username",
        "rdp_password",
        "os-username",
        "os-password",
    ] {
        if let Some(v) = old.options.get(key) {
            fresh.options.insert(key.to_owned(), v.clone());
        }
    }
    fresh.store(&id);
    log::info!("peer {}: preferences reset to defaults", id);
    true
}

/// Every id with a published direct endpoint, sorted and comma-joined: a cheap
/// fingerprint a UI compares periodically to redraw its Direct chips.
pub fn nemo_direct_ids() -> String {
    let mut ids = crate::nemo_direct::direct_capable_ids();
    ids.sort();
    ids.join(",")
}

/// Set / clear the one-shot "direct only, do not fall back to the relay" flag for `id`
/// (consumed by the next connection, client.rs take_force_direct).
pub fn nemo_set_force_direct(id: String, on: bool) {
    set_peer_option(
        id,
        crate::nemo_direct::PEER_OPTION_FORCE_DIRECT.to_owned(),
        if on { "Y".to_owned() } else { String::new() },
    );
}

/// "Copy recent log": the redacted tail of the main log and of the newest session log,
/// with a header naming this build and machine. Ok((text, files)) or Err(log dir) when
/// there was nothing to read. The caller puts `text` on the clipboard.
pub fn nemo_recent_log() -> Result<(String, Vec<String>), String> {
    let header = vec![
        format!(
            "TBFDesk {} (build {})  id {}  {}",
            crate::VERSION,
            get_build_id(),
            hbb_common::config::Config::get_id(),
            hbb_common::chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z")
        ),
        format!(
            "platform {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
        // The background service writes its own log, under a profile this user
        // usually cannot read. Say where it is rather than pretending it is here.
        "service log: not included (it lives in the service's own profile and needs \
             administrator rights to read)"
            .to_owned(),
    ];
    let (text, files) = crate::nemo_logs::collect(&Config::log_path(), &header);
    if files.is_empty() {
        return Err(Config::log_path().display().to_string());
    }
    Ok((
        text,
        files.iter().map(|f| f.display().to_string()).collect(),
    ))
}

/// "Open log folder": the log root (main log + `connect/` with the session logs).
/// "" on success, otherwise the error.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn nemo_open_log_folder() -> String {
    match crate::nemo_logs::open_folder(&Config::log_path()) {
        Ok(()) => String::new(),
        Err(err) => err.to_string(),
    }
}

/// Open a folder (the recording directory) in the system file manager, creating it if
/// missing. Windows: explorer with a backslash path (UNC / roaming-profile shares
/// included). Not open_url: on Linux that prefers firefox.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn open_folder(path: String) {
    let path = path.trim();
    if path.is_empty() {
        return;
    }
    let path = path.strip_prefix("file://").unwrap_or(path);
    #[cfg(windows)]
    let path = path.replace('/', "\\");
    #[cfg(not(windows))]
    let path = path.to_owned();
    let dir = std::path::Path::new(&path);
    if !dir.exists() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log::error!("Failed to create folder {}: {}", path, e);
            return;
        }
    }
    #[cfg(windows)]
    let p = "explorer";
    #[cfg(target_os = "macos")]
    let p = "open";
    #[cfg(not(any(windows, target_os = "macos")))]
    let p = "xdg-open";
    allow_err!(std::process::Command::new(p).arg(&path).spawn());
}

// ---------------------------------------------------------------------------------------
// H25, shared by both UIs: the peer password for a command-line launch, never from argv.
// Sciter calls peer_password_from_args (ui.rs). Flutter resolves --password-file /
// --password-stdin in core_main (peer_password_from_secret_flags) BEFORE Flutter starts:
// handed to a running instance inside the URL (D-Bus / window message, not argv), or kept
// here for this process's Dart side to take once (main_nemo_take_boot_password).
// ---------------------------------------------------------------------------------------
/// H25: resolve the peer password without requiring it on the command line.
///
/// A positional password is visible in `/proc/<pid>/cmdline` -- which is world-readable --
/// for the WHOLE session, because the Sciter GUI runs in this same process. It also lands
/// in shell history. Two safe alternatives are accepted instead:
///
///   --password-stdin        read one line from stdin
///   --password-file <path>  read it from a file, refused if group/other-readable
///
/// The positional form still works so existing runbooks do not break, but it warns. It is
/// now also guarded against swallowing the next FLAG: `--connect <id> --relay` used to set
/// the password to the literal "--relay".
///
/// Returns (password, remaining args) -- the password-bearing arguments are removed so
/// they are not re-parsed downstream.
pub fn peer_password_from_args(rest: &[String]) -> (String, Vec<String>) {
    let mut out = Vec::with_capacity(rest.len());
    let mut pass: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--password-stdin" => {
                let mut line = String::new();
                match std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line) {
                    Ok(_) => pass = Some(line.trim_end_matches(['\n', '\r']).to_owned()),
                    Err(err) => log::error!("failed to read the password from stdin: {err}"),
                }
                i += 1;
            }
            "--password-file" => {
                match rest.get(i + 1) {
                    Some(path) => match read_peer_password_file(path) {
                        Ok(v) => pass = Some(v),
                        Err(err) => log::error!("failed to read {path}: {err}"),
                    },
                    None => log::error!("--password-file needs a path"),
                }
                i += 2;
            }
            // The positional password, but only if it is not a flag.
            other if pass.is_none() && out.is_empty() && !other.starts_with("--") => {
                eprintln!(
                    "warning: passing the peer password as an argument exposes it in `ps` \
                     for the whole session; prefer --password-stdin or --password-file"
                );
                pass = Some(other.to_owned());
                i += 1;
            }
            _ => {
                out.push(rest[i].clone());
                i += 1;
            }
        }
    }
    (pass.unwrap_or_default(), out)
}

pub fn read_peer_password_file(path: &str) -> std::io::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{path} is readable by group or other (mode {:o})", mode & 0o777),
            ));
        }
    }
    Ok(std::fs::read_to_string(path)?
        .trim_end_matches(['\n', '\r'])
        .to_owned())
}

/// Only the two safe forms (--password-stdin, --password-file <path>), for a launch path
/// whose positional arguments are not a password (Flutter: `rustdesk --connect <id> ...`).
/// Returns (password if one was given, the arguments with those flags removed).
pub fn peer_password_from_secret_flags(args: &[String]) -> (Option<String>, Vec<String>) {
    let mut out = Vec::with_capacity(args.len());
    let mut pass = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--password-stdin" | "--password-file" => {
                let n = if args[i] == "--password-file" { 2 } else { 1 };
                let (p, _) = peer_password_from_args(&args[i..(i + n).min(args.len())]);
                if !p.is_empty() {
                    pass = Some(p);
                }
                i += n;
            }
            _ => {
                out.push(args[i].clone());
                i += 1;
            }
        }
    }
    (pass, out)
}

static NEMO_BOOT_PEER_PASSWORD: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Keep the launch password for this process's own Flutter UI (no running instance).
pub fn nemo_set_boot_peer_password(password: String) {
    if let Ok(mut p) = NEMO_BOOT_PEER_PASSWORD.lock() {
        *p = Some(password);
    }
}

/// The launch password, once: a second call (or no password given) returns "".
pub fn nemo_take_boot_peer_password() -> String {
    NEMO_BOOT_PEER_PASSWORD
        .lock()
        .ok()
        .and_then(|mut p| p.take())
        .unwrap_or_default()
}

#[cfg(test)]
mod nemo_h25_tests {
    use super::{peer_password_from_args, peer_password_from_secret_flags};

    /// H25. The positional form must keep working (runbooks), but it must not swallow a
    /// flag -- `--connect <id> --relay` used to set the password to "--relay", which both
    /// leaked nothing and broke the flag.
    #[test]
    fn a_flag_is_never_taken_as_the_peer_password() {
        let (pass, rest) = peer_password_from_args(&["--relay".to_owned()]);
        assert_eq!(pass, "");
        assert_eq!(rest, vec!["--relay".to_owned()]);

        let (pass, rest) = peer_password_from_args(&["hunter2".to_owned(), "--relay".to_owned()]);
        assert_eq!(pass, "hunter2");
        assert_eq!(rest, vec!["--relay".to_owned()]);

        let (pass, rest) = peer_password_from_args(&[]);
        assert_eq!(pass, "");
        assert!(rest.is_empty());
    }

    /// The password-bearing arguments are consumed, so they are not re-parsed downstream
    /// and cannot reach a session as an option.
    #[test]
    fn password_file_argument_is_consumed() {
        let (_pass, rest) = peer_password_from_args(&[
            "--password-file".to_owned(),
            "/nonexistent".to_owned(),
            "--relay".to_owned(),
        ]);
        assert_eq!(rest, vec!["--relay".to_owned()]);
    }

    /// Flutter launch path: only the safe forms are taken; the id and other flags stay.
    #[test]
    fn secret_flags_only_take_the_safe_forms() {
        let args: Vec<String> = ["--connect", "123", "--password-file", "/nonexistent", "--relay"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (pass, rest) = peer_password_from_secret_flags(&args);
        assert_eq!(pass, None); // unreadable file: no password, but the flag is consumed
        assert_eq!(rest, vec!["--connect", "123", "--relay"]);
    }
}
