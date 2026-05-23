use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    config::{keys, Config},
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
const MANAGED_OPTION_KEYS: &[&str] = &[
    keys::OPTION_ENABLE_KEYBOARD,
    keys::OPTION_ENABLE_CLIPBOARD,
    keys::OPTION_ENABLE_FILE_TRANSFER,
    keys::OPTION_ENABLE_CAMERA,
    keys::OPTION_ENABLE_TERMINAL,
    keys::OPTION_ENABLE_AUDIO,
    keys::OPTION_ENABLE_TUNNEL,
    keys::OPTION_ENABLE_REMOTE_RESTART,
    keys::OPTION_ENABLE_RECORD_SESSION,
    keys::OPTION_ENABLE_BLOCK_INPUT,
    keys::OPTION_ENABLE_PRIVACY_MODE,
    keys::OPTION_ENABLE_REMOTE_PRINTER,
    keys::OPTION_ALLOW_REMOTE_CONFIG_MODIFICATION,
    keys::OPTION_ENABLE_LAN_DISCOVERY,
];

#[derive(Default, Deserialize, Serialize)]
struct ManagementPolicy {
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
    let previous = previous_policy_options();
    for key in previous.keys() {
        if !policy.options.contains_key(key) && is_managed_option(key) {
            Config::set_option(key.to_owned(), String::new());
        }
    }
    for (key, value) in &policy.options {
        if !is_managed_option(key) {
            continue;
        }
        let Some(normalized) = normalize_policy_value(value) else {
            continue;
        };
        if Config::get_option(key) != normalized {
            Config::set_option(key.to_owned(), normalized);
        }
    }
    Config::set_option(
        OPTION_NEMO_MANAGEMENT_LAST_POLICY.to_owned(),
        serde_json::to_string(&policy)?,
    );
    Ok(())
}

fn previous_policy_options() -> HashMap<String, String> {
    serde_json::from_str::<ManagementPolicy>(&Config::get_option(
        OPTION_NEMO_MANAGEMENT_LAST_POLICY,
    ))
    .map(|policy| policy.options)
    .unwrap_or_default()
}

fn policy_url(server: &str) -> String {
    let server = server.trim().trim_end_matches('/');
    if server.ends_with("/nemo/api/client/policy") {
        server.to_owned()
    } else {
        format!("{server}/nemo/api/client/policy")
    }
}

fn is_managed_option(key: &str) -> bool {
    MANAGED_OPTION_KEYS.contains(&key)
}

fn normalize_policy_value(value: &str) -> Option<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "y" | "yes" | "true" | "on" | "allow" | "allowed" => Some("Y".to_owned()),
        "0" | "n" | "no" | "false" | "off" | "deny" | "denied" => Some("N".to_owned()),
        _ => None,
    }
}
