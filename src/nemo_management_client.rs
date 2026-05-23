use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    config::{self, keys, Config},
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
const MANAGED_SECRET_PLACEHOLDER: &str = "<managed-secret>";
const NEMO_MANAGEMENT_SETTINGS: &[&str] = &[
    OPTION_NEMO_MANAGEMENT_ENABLED,
    OPTION_NEMO_MANAGEMENT_SERVER,
    OPTION_NEMO_MANAGEMENT_PUBLIC_KEY,
    OPTION_NEMO_COMPANY_NETWORK_ONLY,
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
    apply_policy(payload.policy)
}

fn verified_payload(
    response: ClientPolicyResponse,
    public_key: &str,
) -> ResultType<ClientPolicyPayload> {
    if public_key.is_empty() {
        log::debug!("Nemo management public key is empty; applying unsigned policy");
        return Ok(response.payload);
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
