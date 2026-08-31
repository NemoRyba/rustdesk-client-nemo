use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    config::{self, keys, Config, LocalConfig},
    log,
    sodiumoxide::crypto::sign,
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Once, time::Duration};

const POLL_INITIAL_DELAY_SECS: u64 = 10;
const POLL_INTERVAL_SECS: u64 = 30;
const OPTION_NEMO_MANAGEMENT_ENABLED: &str = "nemo-management-enabled";
const OPTION_NEMO_MANAGEMENT_SERVER: &str = "nemo-management-server";
const OPTION_NEMO_MANAGEMENT_PUBLIC_KEY: &str = "nemo-management-public-key";
const OPTION_NEMO_MANAGEMENT_LAST_POLICY: &str = "nemo-management-last-policy";
const OPTION_NEMO_COMPANY_NETWORK_ONLY: &str = "nemo-company-network-only";
const OPTION_NEMO_PERMANENT_PASSWORD: &str = "nemo-permanent-password";
const OPTION_NEMO_OUTBOUND_ENABLED: &str = "nemo-outbound-enabled";
const OPTION_NEMO_OUTBOUND_TARGETS: &str = "nemo-outbound-targets";
const MANAGED_SECRET_PLACEHOLDER: &str = "<managed-secret>";
const NEMO_MANAGEMENT_SETTINGS: &[&str] = &[
    OPTION_NEMO_MANAGEMENT_ENABLED,
    OPTION_NEMO_MANAGEMENT_SERVER,
    OPTION_NEMO_MANAGEMENT_PUBLIC_KEY,
    OPTION_NEMO_COMPANY_NETWORK_ONLY,
    OPTION_NEMO_OUTBOUND_ENABLED,
    OPTION_NEMO_OUTBOUND_TARGETS,
    // Friendly per-client name. Admin can push it as a managed default; if the
    // policy has allow_user_override the user may change it locally, otherwise
    // it is locked (see apply_policy_option).
    "nemo-alias",
    // Identity-based policy signalling (read by the UI login gate).
    // NOTE: "nemo-require-login" is deliberately NOT managed here. Managed keys are
    // applied into OVERWRITE_SETTINGS (in-memory only), and is_option_can_save()
    // then refuses to persist them, so Config::set_option would silently drop the
    // flag. The login gate must know it at startup BEFORE the first policy poll
    // (otherwise the full UI flashes for ~10s before the gate appears), so
    // apply_policy() persists it explicitly to CONFIG2.options via set_option --
    // which only works while the key is absent from OVERWRITE_SETTINGS.
    "nemo-logged-in-user",
];

#[derive(Clone, Copy)]
enum ManagedOptionScope {
    Settings,
    Local,
    Display,
    BuiltIn,
}

#[derive(Default, Deserialize, Serialize, Clone)]
struct ManagementPolicy {
    #[serde(default)]
    allow_user_override: bool,
    #[serde(default)]
    options: HashMap<String, String>,
}

#[derive(Serialize)]
struct ClientPolicyRequest {
    id: String,
    uuid: String,
    policy_version: String,
    /// Logged-in user's session token, so the server returns that user's policy.
    access_token: String,
    /// This peer's hostname, so the server can label the address book with which
    /// computer an ID belongs to.
    hostname: String,
}

#[derive(Deserialize)]
struct HttpResponse {
    status_code: u16,
    body: String,
}

#[derive(Deserialize)]
struct ClientPolicyPayload {
    id: String,
    policy: ManagementPolicy,
}

#[derive(Deserialize)]
struct ClientPolicyResponse {
    signed_payload: String,
    payload: ClientPolicyPayload,
}

pub(crate) fn start() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(POLL_INITIAL_DELAY_SECS));
            loop {
                if management_enabled() {
                    if let Err(err) = sync_policy() {
                        log::warn!("Nemo management sync failed: {}", err);
                    }
                }
                std::thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
            }
        });
    });
}

fn management_enabled() -> bool {
    Config::get_option(OPTION_NEMO_MANAGEMENT_ENABLED) == "Y"
        && !Config::get_option(OPTION_NEMO_MANAGEMENT_SERVER).trim().is_empty()
}

fn sync_policy() -> ResultType<()> {
    let server = Config::get_option(OPTION_NEMO_MANAGEMENT_SERVER);
    let public_key = Config::get_option(OPTION_NEMO_MANAGEMENT_PUBLIC_KEY);
    let id = Config::get_id();
    if id.is_empty() {
        bail!("client id is not ready");
    }
    let request = ClientPolicyRequest {
        id: id.clone(),
        uuid: crate::common::encode64(hbb_common::get_uuid()),
        policy_version: Config::get_option(OPTION_NEMO_MANAGEMENT_LAST_POLICY),
        // Identity-based policy: send the logged-in user's token so the server
        // returns that user's policy (empty when nobody is logged in). The token
        // is written by the UI login via set_local_option -> LOCAL config.
        access_token: LocalConfig::get_option("access_token"),
        // Report our hostname so the server can label the address book.
        hostname: crate::common::hostname(),
    };
    let body = serde_json::to_string(&request)?;
    let headers = serde_json::json!({
        "Accept": "application/json",
        "Content-Type": "application/json"
    })
    .to_string();
    let raw = crate::common::http_request_sync(
        policy_url(&server),
        "post".to_owned(),
        Some(body),
        headers,
    )?;
    let http: HttpResponse = serde_json::from_str(&raw)?;
    if http.status_code != 200 {
        bail!("management server returned HTTP {}", http.status_code);
    }
    let response: ClientPolicyResponse = serde_json::from_str(&http.body)?;
    let payload = verified_payload(response, public_key.trim())?;
    if payload.id != id {
        bail!("management policy id mismatch");
    }
    // Read the two signals before apply_policy() consumes the payload. The server
    // inserts `nemo-logged-in-user` iff it resolved our token to a live session,
    // and inserts `nemo-require-login=Y` only on the no-user path. So "require
    // login, but the server saw no user" means our token was NOT recognised.
    let server_saw_user = payload.policy.options.contains_key("nemo-logged-in-user");
    let server_requires_login = payload
        .policy
        .options
        .get("nemo-require-login")
        .map_or(false, |v| v == "Y");
    apply_policy(payload.policy)?;
    // Stale-session self-heal: we polled WITH a token, yet the server signalled
    // require-login and did not recognise us (server restart wiped its in-memory
    // sessions, or the user was disabled/expired). Drop the dead token so the UI
    // login gate returns instead of the client believing it is still signed in.
    // Race-safe: only clear if the stored token is still exactly the one we polled
    // with, so a login that completed during this request is never discarded.
    if server_requires_login
        && !server_saw_user
        && !request.access_token.is_empty()
        && LocalConfig::get_option("access_token") == request.access_token
    {
        log::info!("Nemo management: session token rejected by server; clearing stale login");
        LocalConfig::set_option("access_token".to_owned(), String::new());
        crate::ui_interface::refresh_options();
    }
    Ok(())
}

fn verified_payload(
    response: ClientPolicyResponse,
    public_key: &str,
) -> ResultType<ClientPolicyPayload> {
    if public_key.is_empty() {
        // Nemo hardening (S1): refuse unsigned policy. Without a configured
        // management public key the client cannot verify the server, so an
        // unsigned payload is forgeable (a MITM could push a password or
        // enable remote config). `nemo-management-allow-unsigned=Y` is a
        // dev/lab-only escape hatch.
        if Config::get_option("nemo-management-allow-unsigned") == "Y" {
            log::warn!("Nemo management public key empty; applying UNSIGNED policy (dev override)");
            return Ok(response.payload);
        }
        bail!("management public key not configured; refusing unsigned policy");
    }
    let pk = crate::common::get_rs_pk(public_key).ok_or_else(|| anyhow!("invalid public key"))?;
    if response.signed_payload.is_empty() {
        bail!("management response is unsigned");
    }
    let signed = crate::common::decode64(&response.signed_payload)?;
    let payload = sign::verify(&signed, &pk).map_err(|_| anyhow!("signature mismatch"))?;
    serde_json::from_slice(&payload).context("invalid signed management payload")
}

fn apply_policy(policy: ManagementPolicy) -> ResultType<()> {
    let previous = previous_policy();
    clear_policy_maps(&previous);
    apply_permanent_password(&policy);
    for (key, value) in &policy.options {
        if key == OPTION_NEMO_PERMANENT_PASSWORD {
            continue;
        }
        if let Some(scope) = option_scope(key) {
            apply_policy_option(scope, key, value, policy.allow_user_override);
        }
    }
    Config::set_option(
        OPTION_NEMO_MANAGEMENT_LAST_POLICY.to_owned(),
        serde_json::to_string(&policy_for_storage(&policy))?,
    );
    // Persist the require-login flag durably so the UI login gate is correct at
    // the very next startup, before the first policy poll completes (avoids a
    // flash of the full UI when login is required).
    Config::set_option(
        "nemo-require-login".to_owned(),
        policy
            .options
            .get("nemo-require-login")
            .cloned()
            .unwrap_or_default(),
    );
    crate::ui_interface::refresh_options();
    Ok(())
}

fn previous_policy() -> ManagementPolicy {
    serde_json::from_str::<ManagementPolicy>(&Config::get_option(
        OPTION_NEMO_MANAGEMENT_LAST_POLICY,
    ))
    .unwrap_or_default()
}

fn apply_permanent_password(policy: &ManagementPolicy) {
    let Some(password) = policy.options.get(OPTION_NEMO_PERMANENT_PASSWORD) else {
        return;
    };
    if crate::common::is_server() {
        Config::set_permanent_password(password);
        log::info!("Nemo management applied incoming access password");
    } else if crate::ui_interface::set_permanent_password_with_result(password.to_owned()) {
        log::info!("Nemo management applied incoming access password through IPC");
    } else {
        log::warn!("Nemo management failed to apply incoming access password");
    }
}

fn policy_for_storage(policy: &ManagementPolicy) -> ManagementPolicy {
    let mut stored = policy.clone();
    for key in secret_policy_keys() {
        if stored.options.contains_key(*key) {
            stored
                .options
                .insert((*key).to_owned(), MANAGED_SECRET_PLACEHOLDER.to_owned());
        }
    }
    stored
}

fn secret_policy_keys() -> &'static [&'static str] {
    &[
        OPTION_NEMO_PERMANENT_PASSWORD,
        keys::OPTION_DEFAULT_CONNECT_PASSWORD,
        keys::OPTION_PROXY_PASSWORD,
        keys::OPTION_PRESET_ADDRESS_BOOK_PASSWORD,
    ]
}

fn policy_url(server: &str) -> String {
    let server = server.trim().trim_end_matches('/');
    if server.ends_with("/nemo/api/client/policy") {
        server.to_owned()
    } else {
        format!("{server}/nemo/api/client/policy")
    }
}

fn clear_policy_maps(policy: &ManagementPolicy) {
    for key in policy.options.keys() {
        if let Some(scope) = option_scope(key) {
            clear_policy_option(scope, key);
        }
    }
}

fn apply_policy_option(
    scope: ManagedOptionScope,
    key: &str,
    value: &str,
    allow_user_override: bool,
) {
    if matches!(scope, ManagedOptionScope::BuiltIn) {
        config::BUILTIN_SETTINGS
            .write()
            .unwrap()
            .insert(key.to_owned(), value.to_owned());
        return;
    }
    let (default_map, overwrite_map) = policy_maps(scope);
    if allow_user_override {
        overwrite_map.write().unwrap().remove(key);
        default_map
            .write()
            .unwrap()
            .insert(key.to_owned(), value.to_owned());
    } else {
        default_map.write().unwrap().remove(key);
        overwrite_map
            .write()
            .unwrap()
            .insert(key.to_owned(), value.to_owned());
    }
}

fn clear_policy_option(scope: ManagedOptionScope, key: &str) {
    if matches!(scope, ManagedOptionScope::BuiltIn) {
        config::BUILTIN_SETTINGS.write().unwrap().remove(key);
        return;
    }
    let (default_map, overwrite_map) = policy_maps(scope);
    default_map.write().unwrap().remove(key);
    overwrite_map.write().unwrap().remove(key);
}

fn policy_maps(
    scope: ManagedOptionScope,
) -> (
    &'static std::sync::RwLock<HashMap<String, String>>,
    &'static std::sync::RwLock<HashMap<String, String>>,
) {
    match scope {
        ManagedOptionScope::Settings => (&config::DEFAULT_SETTINGS, &config::OVERWRITE_SETTINGS),
        ManagedOptionScope::Local => (
            &config::DEFAULT_LOCAL_SETTINGS,
            &config::OVERWRITE_LOCAL_SETTINGS,
        ),
        ManagedOptionScope::Display => (
            &config::DEFAULT_DISPLAY_SETTINGS,
            &config::OVERWRITE_DISPLAY_SETTINGS,
        ),
        ManagedOptionScope::BuiltIn => unreachable!(),
    }
}

fn option_scope(key: &str) -> Option<ManagedOptionScope> {
    if keys::KEYS_SETTINGS.contains(&key) || NEMO_MANAGEMENT_SETTINGS.contains(&key) {
        Some(ManagedOptionScope::Settings)
    } else if keys::KEYS_LOCAL_SETTINGS.contains(&key) {
        Some(ManagedOptionScope::Local)
    } else if keys::KEYS_DISPLAY_SETTINGS.contains(&key) {
        Some(ManagedOptionScope::Display)
    } else if keys::KEYS_BUILDIN_SETTINGS.contains(&key) {
        Some(ManagedOptionScope::BuiltIn)
    } else {
        None
    }
}
