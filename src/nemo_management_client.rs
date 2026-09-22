use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    config::{self, keys, Config, LocalConfig},
    log,
    sodiumoxide::crypto::sign,
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Mutex, Once},
    time::{Duration, Instant},
};

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
// Scope (b): "v1" => wrap the whole poll body in one sealedbox to the management
// key (see poll_request_body). "" (the default) = today's plaintext body.
const OPTION_NEMO_SEALED_REQUEST: &str = "nemo-sealed-request";
// Scope (c): "Y" => fail closed on an unsecured rendezvous connection. "" (the
// default) = today's behaviour. Only plumbed here; read by the rendezvous side.
const OPTION_NEMO_REQUIRE_SECURE_RENDEZVOUS: &str = "nemo-require-secure-rendezvous";
// Auto-update: "Y" => OUR updater (signed manifest from the management server,
// verified against the pinned management key) may run. Enabled only by this Nemo
// policy key — the stock `allow-auto-update` stays in POLICY_DENIED_KEYS, so the
// upstream updater has no way in. "" (the default) = no updater at all.
const OPTION_NEMO_AUTO_UPDATE: &str = "nemo-auto-update";
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
    // S-B item 5: SHA-256 fingerprint to pin the nemo-api TLS cert to. Managed so a
    // whole fleet can be pinned centrally; persisted durably by apply_policy (like
    // api-server) so it is available at the very first request before any poll.
    "nemo-api-cert-fingerprint",
    // Scope (b)/(c) kill switches. Both default to "" = exactly today's behaviour.
    // They MUST be listed here: option_scope() drops any key that is not, so without
    // these two entries the server could push them and every client would silently
    // discard them.
    OPTION_NEMO_SEALED_REQUEST,
    OPTION_NEMO_REQUIRE_SECURE_RENDEZVOUS,
    // Auto-update: same reason — an unlisted key is dropped by option_scope().
    OPTION_NEMO_AUTO_UPDATE,
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
    /// A1: omitted from the wire when `sealed_token` is present (sealed to the mgmt
    /// key so a MITM cannot read it); kept for backward compat when sealing is not
    /// possible (no mgmt key).
    #[serde(skip_serializing_if = "String::is_empty")]
    access_token: String,
    /// A1: base64 sealedbox({token, ts}) to the server's management key — confidential
    /// regardless of TLS. Present instead of `access_token` when a mgmt key is set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sealed_token: String,
    /// This peer's hostname, so the server can label the address book with which
    /// computer an ID belongs to.
    hostname: String,
    /// S-DUALKEY: the provisioned device public key + a signature over
    /// "nemo-poll:{id}:{ts}", proving this client holds its own private key.
    /// Empty when no device key has been imported (server falls back to auth mode
    /// "default").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    device_key_pub: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    device_key_sig: String,
    /// S-B/S-DUALKEY step 3: "v1" advertises that this client can unseal a policy
    /// response sealed to its device key. Empty when no device key is imported.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sealed: String,
}

// Device-key sign/unseal helpers live in crate::common (always compiled) so the
// Sciter UI bridge can reach them too; re-exported here for the poll's use.
use crate::common::{nemo_device_sign, nemo_unseal_with_device_key};

fn nemo_sign_poll(id: &str) -> (String, String) {
    nemo_device_sign("nemo-poll", id)
}

#[derive(Deserialize)]
struct HttpResponse {
    status_code: u16,
    body: String,
}

#[derive(Deserialize)]
struct ClientPolicyPayload {
    id: String,
    /// A2: epoch seconds the server stamped this policy. Used for anti-replay /
    /// anti-rollback (monotonic high-water + absolute staleness). 0 = older server
    /// that does not stamp it (accepted for backward compat, logged).
    #[serde(default)]
    issued_ts: u64,
    /// Server-issued session revocation: terminate any session that is open when a
    /// value NEWER than the one we last acted on arrives. Carried inside the signed
    /// (and, when sealed, encrypted) payload, so it inherits the poll's authenticity
    /// — a MITM cannot forge or strip it without breaking the signature.
    /// 0 / absent = nothing to do (older server, or no revocation issued).
    #[serde(default)]
    terminate_sessions_before: u64,
    policy: ManagementPolicy,
}

#[derive(Deserialize)]
struct ClientPolicyResponse {
    #[serde(default)]
    signed_payload: String,
    #[serde(default)]
    payload: Option<ClientPolicyPayload>,
    /// S-B/S-DUALKEY step 3: base64(sealedbox(sign::sign(payload_json), our device
    /// key)). Present instead of signed_payload/payload when the server sealed the
    /// response to us.
    #[serde(default)]
    sealed_payload: Option<String>,
}

// Once the server has answered us with a SEALED policy response, a later plaintext
// response is a downgrade attempt (a MITM stripping the seal); refuse it. Persisted
// so the ratchet survives restarts. Keyed off the config option below.
const OPTION_NEMO_POLICY_SEAL_SEEN: &str = "nemo-policy-seal-seen";

fn policy_seal_ratchet_engaged() -> bool {
    Config::get_option(OPTION_NEMO_POLICY_SEAL_SEEN) == "Y"
}
fn engage_policy_seal_ratchet() {
    if !policy_seal_ratchet_engaged() {
        Config::set_option(OPTION_NEMO_POLICY_SEAL_SEEN.to_owned(), "Y".to_owned());
    }
}

// A2: highest policy issued_ts we have accepted, persisted so anti-rollback survives
// restarts. The monotonic check is clock-skew-free (compares two server timestamps);
// the absolute window bounds how long a captured fixed blob stays replayable.
const OPTION_NEMO_POLICY_ISSUED_TS: &str = "nemo-policy-issued-ts";
// Generous both ways so NTP-synced fleet clocks never reject a genuine response, while
// still ageing out a replayed fixed blob within the window.
const POLICY_MAX_AGE_SECS: u64 = 600;
const POLICY_MAX_FUTURE_SECS: u64 = 600;

fn policy_issued_ts_high_water() -> u64 {
    Config::get_option(OPTION_NEMO_POLICY_ISSUED_TS)
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
}

// A2: reject a replayed/rolled-back policy. `now` is the client clock (epoch secs).
// Pure so it is unit-testable. Returns Ok(()) to accept, Err(reason) to refuse.
/// Persisted high-water mark of the last revocation we honoured, so the directive is
/// idempotent: the server keeps sending the same timestamp until it issues a new one,
/// and we must not re-kill sessions that were opened legitimately after we acted.
const OPTION_NEMO_TERMINATE_ACKED: &str = "nemo-terminate-acked";

fn terminate_acked() -> u64 {
    Config::get_option(OPTION_NEMO_TERMINATE_ACKED)
        .parse::<u64>()
        .unwrap_or(0)
}

fn apply_session_revocation(terminate_sessions_before: u64) {
    if terminate_sessions_before == 0 {
        return;
    }
    let acked = terminate_acked();
    if terminate_sessions_before <= acked {
        return; // already honoured this one
    }
    // Record BEFORE acting. If the process dies mid-teardown the sessions are gone
    // with it anyway, whereas recording afterwards could re-fire the kill on every
    // poll if the write failed.
    Config::set_option(
        OPTION_NEMO_TERMINATE_ACKED.to_owned(),
        terminate_sessions_before.to_string(),
    );
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let n = crate::server::terminate_all_authed_sessions(&format!(
            "server revoked sessions (terminate_sessions_before={terminate_sessions_before})"
        ));
        if n > 0 {
            log::warn!("Server-issued revocation closed {n} session(s)");
        }
    }
}

fn check_policy_freshness(issued_ts: u64, high_water: u64, now: u64) -> Result<(), String> {
    if issued_ts == 0 {
        // Older server that does not stamp issued_ts — no rollback protection possible;
        // accept for backward compatibility (the signature still guarantees authenticity).
        return Ok(());
    }
    // Anti-rollback: never step to an OLDER policy than one we already applied.
    if issued_ts < high_water {
        return Err(format!(
            "policy issued_ts {issued_ts} is older than last-applied {high_water} (rollback/replay refused)"
        ));
    }
    // Absolute staleness: a captured fixed blob (issued_ts == high_water) ages out here,
    // so a MITM cannot pin the client to a stale-but-not-older policy indefinitely.
    if now.saturating_sub(issued_ts) > POLICY_MAX_AGE_SECS {
        return Err(format!(
            "policy issued_ts {issued_ts} is stale (> {POLICY_MAX_AGE_SECS}s old; replay refused)"
        ));
    }
    if issued_ts.saturating_sub(now) > POLICY_MAX_FUTURE_SECS {
        return Err(format!(
            "policy issued_ts {issued_ts} is too far in the future (> {POLICY_MAX_FUTURE_SECS}s; refused)"
        ));
    }
    Ok(())
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

/// Scope (b) / Layer 1: turn the plain poll body into `{"sealed_request": "<b64>"}`
/// and nothing else. The sealed plaintext is the body we would have posted today, so
/// A1's `sealed_token` and everything else rides inside the envelope unchanged.
///
/// Layer 1 makes the envelope MANDATORY whenever a management public key is
/// configured (`mgmt_key_configured`), independent of the `nemo-sealed-request`
/// flag: the body carries the device signature and the session token, and a
/// plaintext fallback would hand both to a TLS-stripping MITM. So with a key present
/// a failed seal yields `None` — the caller skips this poll and retries next tick —
/// and never the plaintext body. This adds no brick surface: the only way sealing
/// fails with a key present is a key that get_rs_pk rejects, and that same key
/// already fails verified_payload, so policy sync was dead regardless.
///
/// Without a management key today's behaviour stands: the plain body; and if the
/// flag is set anyway, the B1 brick lesson applies — post the plain body and warn,
/// because losing policy sync forever is worse than a readable poll. (The flag still
/// gates /api/ab/get, see common::nemo_sealed_request_enabled.)
///
/// `seal` is injected rather than called directly so every branch is testable
/// without a management key in Config.
fn poll_request_body(
    plain: String,
    seal_enabled: bool,
    mgmt_key_configured: bool,
    seal: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    if !seal_enabled && !mgmt_key_configured {
        return Some(plain);
    }
    match seal(&plain) {
        Some(sealed) => Some(serde_json::json!({ "sealed_request": sealed }).to_string()),
        None if mgmt_key_configured => None,
        None => {
            log::warn!("Nemo management: nemo-sealed-request is set but this client cannot seal the poll (no management public key?); posting the unsealed body");
            Some(plain)
        }
    }
}

// Layer 1: an unprovisioned machine is refused on every poll (every 30s); the line
// that says what to do is printed at most once per DEVICE_KEY_REJECTION_LOG_INTERVAL
// so the log stays readable. std Mutex, not tokio: the poll loop is a plain thread.
const DEVICE_KEY_REJECTION_LOG_INTERVAL: Duration = Duration::from_secs(60);
static LAST_DEVICE_KEY_REJECTION_LOG: Mutex<Option<Instant>> = Mutex::new(None);

fn device_key_rejection_log_due() -> bool {
    // A poisoned lock means a panic elsewhere, not a throttling decision: log anyway.
    let Ok(mut last) = LAST_DEVICE_KEY_REJECTION_LOG.lock() else {
        return true;
    };
    rejection_log_due(&mut last, Instant::now(), DEVICE_KEY_REJECTION_LOG_INTERVAL)
}

// Pure so the throttle is unit-testable: true (and records `now`) when no line has
// been printed within `interval`.
fn rejection_log_due(last: &mut Option<Instant>, now: Instant, interval: Duration) -> bool {
    if let Some(t) = *last {
        if now.duration_since(t) < interval {
            return false;
        }
    }
    *last = Some(now);
    true
}

// The server's ApiError shape is `{"error": "<message>"}`; surface that verbatim so
// the operator reads the server's own reason. Anything else (an intermediary's HTML
// page, an empty body) is bounded so it cannot flood the log.
fn http_error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| body.chars().take(200).collect())
}

fn sync_policy() -> ResultType<()> {
    let server = Config::get_option(OPTION_NEMO_MANAGEMENT_SERVER);
    let public_key = Config::get_option(OPTION_NEMO_MANAGEMENT_PUBLIC_KEY);
    let id = Config::get_id();
    if id.is_empty() {
        bail!("client id is not ready");
    }
    // Identity-based policy: send the logged-in user's token so the server returns that
    // user's policy (empty when nobody is logged in). A1: seal it to the mgmt key so a
    // MITM on the poll channel cannot read the session token; fall back to plaintext only
    // when no mgmt key is configured (then TLS is the sole protection).
    let polled_token = LocalConfig::get_option("access_token");
    let access_token = polled_token.clone();
    let (access_token, sealed_token) = if access_token.is_empty() {
        (String::new(), String::new())
    } else {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let blob = serde_json::json!({ "token": access_token, "ts": ts }).to_string();
        match crate::common::nemo_seal_to_mgmt_key(blob.as_bytes()) {
            Some(sealed) => (String::new(), sealed),
            None => (access_token, String::new()),
        }
    };
    let request = ClientPolicyRequest {
        id: id.clone(),
        uuid: crate::common::encode64(hbb_common::get_uuid()),
        policy_version: Config::get_option(OPTION_NEMO_MANAGEMENT_LAST_POLICY),
        access_token,
        sealed_token,
        // Report our hostname so the server can label the address book.
        hostname: crate::common::hostname(),
        device_key_pub: String::new(),
        device_key_sig: String::new(),
        sealed: String::new(),
    };
    let (device_key_pub, device_key_sig) = nemo_sign_poll(&id);
    // Layer 1: remembered so the server's refusal can be explained below. The poll
    // still goes out WITHOUT a device key — the server records this peer's auth mode
    // ("default") for the Peers dashboard before it refuses, and that column is the
    // rollout instrument.
    let has_device_key = !device_key_pub.is_empty();
    // Only advertise seal support when we actually hold a device key to unseal with.
    let sealed = if device_key_pub.is_empty() {
        String::new()
    } else {
        "v1".to_owned()
    };
    let request = ClientPolicyRequest {
        device_key_pub,
        device_key_sig,
        sealed,
        ..request
    };
    let mgmt_key_configured = !public_key.trim().is_empty();
    let Some(body) = poll_request_body(
        serde_json::to_string(&request)?,
        crate::common::nemo_sealed_request_enabled(),
        mgmt_key_configured,
        crate::common::nemo_seal_envelope,
    ) else {
        // Layer 1: a management key is configured, so the envelope is mandatory and
        // the plaintext body must not go out. The body is always a serialized struct,
        // so the only cause left is the key itself.
        let cause = if crate::common::get_rs_pk(public_key.trim()).is_none() {
            "nemo-management-public-key is not a valid Ed25519 public key"
        } else {
            "sealing to the management public key failed"
        };
        log::error!(
            "Nemo management: Layer 1 requires the poll to be sealed while a management public key is configured, but {}; skipping this poll (not posting plaintext), retrying next tick",
            cause
        );
        bail!("poll skipped: sealed envelope required but could not be built ({cause})");
    };
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
        let server_msg = http_error_message(&http.body);
        // Layer 1: the server refuses (403) a poll without a valid, PINNED device
        // signature. Keyed off the status + our own key presence, not the server's
        // wording, so a reworded message cannot silence it; the wording is echoed.
        if http.status_code == 403 && !has_device_key {
            if device_key_rejection_log_due() {
                log::error!(
                    "Nemo management: the server REFUSED this client's poll (HTTP 403: {}) and NO DEVICE KEY is provisioned on this machine. Layer 1 requires one: import the device key issued for this machine (main window -> Import device key, or the licence-name bootstrap). Policy sync is blocked until then. (repeats at most once per minute)",
                    server_msg
                );
            }
            // Ok, not bail!: the throttled line above IS the report. An Err here
            // would make start() print an unthrottled warn every 30s on top of it
            // and defeat the once-per-minute rule.
            return Ok(());
        }
        if http.status_code == 403 && server_msg.to_ascii_lowercase().contains("device key") {
            // We DO hold a device key and the server still refused it: it is not the
            // one pinned for this id (rotated, re-provisioned, or never pinned).
            bail!(
                "management server refused this client's device key (HTTP 403: {}). The key on this machine is not the one pinned for id {} — re-pin it in the dashboard's Device keys panel or import the currently pinned key",
                server_msg,
                id
            );
        }
        bail!(
            "management server returned HTTP {} ({})",
            http.status_code,
            server_msg
        );
    }
    let response: ClientPolicyResponse = serde_json::from_str(&http.body)?;
    let was_sealed = response.sealed_payload.is_some();
    let payload = verified_payload(response, public_key.trim())?;
    // Anti-downgrade ratchet: once we have received a sealed response, a later
    // UNSEALED one means a MITM stripped the seal — refuse it. (A server that
    // genuinely stops sealing would also stop pushing secrets, but we must not let
    // an attacker choose the plaintext path for us.)
    if was_sealed {
        engage_policy_seal_ratchet();
    } else if policy_seal_ratchet_engaged() {
        // B1: only enforce the ratchet while we STILL hold a device key. Without one we
        // cannot unseal anyway, so a plaintext response is legitimate (config reset / key
        // removed) — refusing it forever would brick policy sync. With a key present, an
        // unsealed response is the downgrade signal, so refuse it.
        if crate::common::nemo_device_ed25519().is_some() {
            bail!("management policy response was not sealed but this client holds a device key and requires sealing (possible downgrade attack). If this client was intentionally deprovisioned, clear option nemo-policy-seal-seen or re-pin its device key.");
        }
        log::warn!("Nemo management: seal ratchet was engaged but no device key is present now; accepting plaintext policy and clearing the ratchet");
        Config::set_option(OPTION_NEMO_POLICY_SEAL_SEEN.to_owned(), String::new());
    }
    if payload.id != id {
        bail!("management policy id mismatch");
    }
    // A2: anti-replay / anti-rollback. The response is authenticated (signature verified
    // above), but a MITM can REPLAY an old authentic response to roll security state
    // backward (revert a rotated password, clear the blocklist, drop require-encrypted).
    // Reject anything older than the newest policy we have applied, and age out a fixed
    // stale blob. Applies to sealed and plaintext responses alike (issued_ts is signed).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let high_water = policy_issued_ts_high_water();
    if let Err(reason) = check_policy_freshness(payload.issued_ts, high_water, now) {
        bail!("management policy rejected: {reason}");
    }
    if payload.issued_ts == 0 {
        log::warn!("Nemo management: policy has no issued_ts (older server); rollback protection unavailable");
    } else if payload.issued_ts > high_water {
        Config::set_option(
            OPTION_NEMO_POLICY_ISSUED_TS.to_owned(),
            payload.issued_ts.to_string(),
        );
    }
    // Read the two signals before apply_policy() consumes the payload. The server
    // inserts `nemo-logged-in-user` iff it resolved our token to a live session,
    // and inserts `nemo-require-login=Y` only on the no-user path. So "require
    // login, but the server saw no user" means our token was NOT recognised.
    // Session revocation. Deliberately acted on BEFORE apply_policy: if an operator
    // cut this device, the sessions should drop even if applying the rest of the
    // policy were to fail. Idempotent via a persisted high-water mark, so a repeated
    // poll carrying the same value does not keep killing freshly-opened sessions.
    apply_session_revocation(payload.terminate_sessions_before);
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
        && !polled_token.is_empty()
        && LocalConfig::get_option("access_token") == polled_token
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
        // dev/lab-only escape hatch that is compiled out of release builds.
        if nemo_allow_unsigned_policy() {
            log::warn!("Nemo management public key empty; applying UNSIGNED policy (dev override)");
            // A sealed response cannot be honoured without a signing key to verify
            // it against; only the plaintext dev path is meaningful here.
            if let Some(payload) = response.payload {
                return Ok(payload);
            }
            bail!("sealed policy response but no management public key to verify it");
        }
        bail!("management public key not configured; refusing unsigned policy");
    }
    let pk = crate::common::get_rs_pk(public_key).ok_or_else(|| anyhow!("invalid public key"))?;
    // S-B/S-DUALKEY step 3: sealed response — unseal to the device key, THEN verify
    // the Ed25519 signature that was sealed inside (sign-then-seal). This keeps the
    // exact S1 anti-forgery property (a MITM cannot forge policy) while adding
    // confidentiality (a MITM cannot read the pushed password / peer list).
    if let Some(sealed_b64) = response.sealed_payload.as_deref() {
        let opened = nemo_unseal_with_device_key(sealed_b64)
            .ok_or_else(|| anyhow!("could not unseal management policy response to device key"))?;
        let payload = sign::verify(&opened, &pk)
            .map_err(|_| anyhow!("sealed policy signature mismatch"))?;
        return serde_json::from_slice(&payload)
            .context("invalid sealed management payload");
    }
    let Some(_payload) = &response.payload else {
        bail!("management response has neither a signed nor a sealed payload");
    };
    if response.signed_payload.is_empty() {
        bail!("management response is unsigned");
    }
    let signed = crate::common::decode64(&response.signed_payload)?;
    let payload = sign::verify(&signed, &pk).map_err(|_| anyhow!("signature mismatch"))?;
    serde_json::from_slice(&payload).context("invalid signed management payload")
}

// L-fix: the unsigned-policy escape hatch must not exist in release builds. In a
// debug build it is still a runtime opt-in (`nemo-management-allow-unsigned=Y`).
#[cfg(debug_assertions)]
fn nemo_allow_unsigned_policy() -> bool {
    Config::get_option("nemo-management-allow-unsigned") == "Y"
}
#[cfg(not(debug_assertions))]
fn nemo_allow_unsigned_policy() -> bool {
    false
}

fn apply_policy(policy: ManagementPolicy) -> ResultType<()> {
    let previous = previous_policy();
    clear_policy_maps(&previous);
    // Persist STARTUP-CRITICAL connectivity options durably HERE — after the
    // previous policy's copy has been cleared from the in-memory OVERWRITE map and
    // BEFORE the loop below re-applies it — because is_option_can_save() refuses to
    // persist a key that is currently in OVERWRITE. Without this these live only in
    // OVERWRITE (empty at startup and briefly during each poll), so at launch,
    // before the first poll, the client cannot reach the server: `api-server` falls
    // back to the default http://<host>:21114 derivation, and `allow-insecure-tls-
    // fallback` is off so TLS to the self-signed https API is rejected
    // ("untrusted root"). Reading them back later still prefers the OVERWRITE
    // (managed) value; this is only the durable startup fallback.
    for k in [
        "api-server",
        "allow-insecure-tls-fallback",
    ] {
        if let Some(v) = policy.options.get(k) {
            if !v.trim().is_empty() {
                Config::set_option(k.to_owned(), v.clone());
            }
        }
    }
    // Scope (b)/(c) flags — same startup-critical reason as the block above (the
    // rendezvous mediator comes up ~10s before the first poll, so an OVERWRITE-only
    // value is off on every boot) and the same placement constraint, only more
    // sharply: unlike "nemo-require-login" these two ARE in NEMO_MANAGEMENT_SETTINGS,
    // so once the loop below has put them into OVERWRITE_SETTINGS, is_option_can_save()
    // would refuse the write and set_option would DELETE the persisted copy instead.
    // Hence here, between the clear and the re-apply.
    // unwrap_or_default() is deliberate and must stay: a policy that STOPS sending the
    // key CLEARS it, which is the un-brick path for a fleet locked out by its own flag.
    for k in [
        OPTION_NEMO_SEALED_REQUEST,
        OPTION_NEMO_REQUIRE_SECURE_RENDEZVOUS,
        // Auto-update: the updater must know at startup whether it may run, and a
        // policy that stops sending the key must switch it OFF — same clear-on-omit.
        OPTION_NEMO_AUTO_UPDATE,
    ] {
        Config::set_option(
            k.to_owned(),
            policy.options.get(k).cloned().unwrap_or_default(),
        );
    }
    // Review finding: the cert pin used to be write-once — set only when non-empty, with
    // no way to clear it. One malformed or hostile value permanently killed the only
    // channel that could deliver a correction (policy arrives over the pinned URL), and
    // it survived reboots. Now it has the same clear-on-omit semantics as the flags
    // above, and a value that is not a SHA-256 fingerprint is refused rather than stored.
    {
        let k = "nemo-api-cert-fingerprint";
        let v = policy.options.get(k).cloned().unwrap_or_default();
        let v = if v.trim().is_empty() {
            String::new()
        } else if crate::common::parse_fingerprint_hex(v.trim()).is_some() {
            v
        } else {
            log::warn!(
                "Nemo management: ignoring malformed {} (expected 64 hex digits); leaving the pin unset",
                k
            );
            String::new()
        };
        Config::set_option(k.to_owned(), v);
    }
    apply_permanent_password(&policy);
    for (key, value) in &policy.options {
        if key == OPTION_NEMO_PERMANENT_PASSWORD {
            continue;
        }
        if policy_key_denied(key) {
            log::warn!(
                "Nemo management: refusing policy key '{}' — it is not applicable to a managed client (see POLICY_DENIED_KEYS)",
                key
            );
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
    // S-A: persist the require-encrypted-session flag so the peer handshake can
    // read it (controller refuses plaintext fallback; controlled refuses an
    // unencrypted session) from the very next connection.
    // The flag now DEFAULTS ON — common.rs::nemo_require_encrypted_session treats
    // anything but an explicit "N" as "required" — so this unwrap_or_default() is
    // fail-closed: a policy that STOPS sending the key returns the machine to
    // "encryption required", it does not re-open the plaintext fallback. Turning
    // the fallback back on takes an explicit, signed "N". Do not "fix" this into
    // a skip-on-absent: clearing must land on the safe side.
    Config::set_option(
        "nemo-require-encrypted-session".to_owned(),
        policy
            .options
            .get("nemo-require-encrypted-session")
            .cloned()
            .unwrap_or_default(),
    );
    // #3-push: persist the address-book version so the UI can notice an ACL change
    // on the next poll and re-fetch the address book (no dedicated push channel).
    Config::set_option(
        "nemo-ab-version".to_owned(),
        policy
            .options
            .get("nemo-ab-version")
            .cloned()
            .unwrap_or_default(),
    );
    // #2: persist the pushed blocklist of source IDs so the controlled side can
    // reject an incoming connection from a blocked peer even if that peer bypasses
    // the server (direct/modified client). Signed, so it can't be forged.
    Config::set_option(
        "nemo-blocked-ids".to_owned(),
        policy
            .options
            .get("nemo-blocked-ids")
            .cloned()
            .unwrap_or_default(),
    );
    // B: persist the signed `{id -> Ed25519 pubkey}` map so a controller can verify a
    // direct-IP peer's SignedId (server-anchored encryption with no rendezvous broker).
    // Signed by the same server key trusted as rs_pk, so it can't be forged.
    Config::set_option(
        "nemo-peer-keys".to_owned(),
        policy
            .options
            .get("nemo-peer-keys")
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

// Review finding (CRITICAL): apply_policy forwards any key that `option_scope` accepts,
// which is every member of hbb_common's KEYS_SETTINGS — including `allow-auto-update`.
// The updater it enables does NOT update this fork: the version URL is hardcoded to
// upstream (`hbb_common/src/lib.rs`, api.rustdesk.com), so a single pushed policy makes
// every Windows workstation silently install stock RustDesk over the hardened build with
// a privileged installer. That removes the login gate, sealed login, signed policy,
// blocked-ids, the cert pin and the licence-named-exe provisioning in one step, and it
// survives the compromise — no key rotation or server rebuild undoes it.
//
// A managed fleet is updated by the operator's own deployment tooling, never by a key a
// policy can set, so these keys are refused here. This is the security boundary: it must
// live on the client, because a compromised server cannot be trusted to omit the key.
// NOTE: the dashboard still offers an "Auto update" checkbox; it is now inert for managed
// clients and should be removed server-side too.
const POLICY_DENIED_KEYS: &[&str] = &["allow-auto-update", "auto-update-check-interval"];

fn policy_key_denied(key: &str) -> bool {
    POLICY_DENIED_KEYS.contains(&key)
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

#[cfg(test)]
mod tests {
    use hbb_common::sodiumoxide::crypto::{sealedbox, sign};

    // S-B/S-DUALKEY step 3: a payload the SERVER sealed to our device pubkey
    // (Ed25519 -> Curve25519 -> sealedbox) is opened by our device secret key, and
    // by no one else. Mirrors seal_to_device_key on the server.
    #[test]
    fn device_key_seal_roundtrip() {
        hbb_common::sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        // Server side: seal to the Curve25519 form of the Ed25519 public key.
        let curve_pk = sign::to_curve25519_pk(&pk).unwrap();
        let sealed = crate::common::encode64(&sealedbox::seal(b"managed-password", &curve_pk));
        // Client side: our unseal helper recovers it.
        let opened =
            crate::common::nemo_unseal_with_device_keys(&sealed, &pk, &sk).expect("unseal");
        assert_eq!(opened, b"managed-password");
        // A different device key cannot open it.
        let (pk2, sk2) = sign::gen_keypair();
        assert!(crate::common::nemo_unseal_with_device_keys(&sealed, &pk2, &sk2).is_none());
        // Garbage ciphertext -> None, never a panic.
        assert!(crate::common::nemo_unseal_with_device_keys("!!!not-base64!!!", &pk, &sk).is_none());
    }

    // A2: anti-replay / anti-rollback freshness gate.
    #[test]
    fn policy_freshness_rejects_replay_and_rollback() {
        use super::check_policy_freshness;
        let now = 1_000_000u64;
        // Fresh, advancing: accepted.
        assert!(check_policy_freshness(now, 0, now).is_ok());
        assert!(check_policy_freshness(now, now - 100, now).is_ok());
        // Equal to high-water but still fresh (same-second re-issue): accepted.
        assert!(check_policy_freshness(now - 10, now - 10, now).is_ok());
        // Older than the high-water mark (rollback to an earlier policy): refused.
        assert!(check_policy_freshness(now - 100, now - 10, now).is_err());
        // Fixed stale blob equal to high-water but aged past the window: refused.
        assert!(check_policy_freshness(now - 601, now - 601, now).is_err());
        // Absurd future timestamp: refused.
        assert!(check_policy_freshness(now + 601, 0, now).is_err());
        // issued_ts == 0 (older server, no stamp): accepted for backward compat.
        assert!(check_policy_freshness(0, now, now).is_ok());
    }

    // Scope (b): the poll body is today's plain shape while nemo-sealed-request is
    // unset, and exactly {"sealed_request": ...} with no other key once it is set.
    #[test]
    fn poll_body_is_plain_until_sealing_is_enabled() {
        use super::poll_request_body;
        let plain = r#"{"id":"123","sealed_token":"AAAA","hostname":"pc"}"#.to_owned();
        // Option unset (today's fleet): byte-for-byte the body we post today, and the
        // injected sealer is never consulted.
        assert_eq!(
            poll_request_body(plain.clone(), false, false, |_| -> Option<String> {
                panic!("must not seal while the option is unset")
            }),
            Some(plain.clone())
        );
        // Opted in: one key and one key only, and nothing else reaches the wire.
        let sealed = poll_request_body(plain.clone(), true, false, |_| Some("c2VhbGVk".to_owned()))
            .expect("sealed body");
        let v: serde_json::Value = serde_json::from_str(&sealed).expect("json object");
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 1);
        assert_eq!(obj["sealed_request"], "c2VhbGVk");
        assert!(!sealed.contains("sealed_token"));
        assert!(!sealed.contains("hostname"));
        // B1 (no management key): opted in but unable to seal -> keep syncing in the
        // clear, never go dark.
        assert_eq!(
            poll_request_body(plain.clone(), true, false, |_| None),
            Some(plain.clone())
        );
    }

    // Layer 1: with a management public key configured the envelope is mandatory —
    // a sealer that fails means NO body (skip this poll), never the plaintext, and
    // the `nemo-sealed-request` flag no longer matters either way.
    #[test]
    fn poll_body_is_never_plaintext_while_a_management_key_is_configured() {
        use super::poll_request_body;
        let plain = r#"{"id":"123","sealed_token":"AAAA","hostname":"pc"}"#.to_owned();
        // Sealer fails, flag set or unset: skip, never plaintext.
        assert!(poll_request_body(plain.clone(), true, true, |_| None).is_none());
        assert!(poll_request_body(plain.clone(), false, true, |_| None).is_none());
        // Sealer works with the flag UNSET: still sealed (mandatory, not opt-in).
        let sealed = poll_request_body(plain.clone(), false, true, |_| Some("c2VhbGVk".to_owned()))
            .expect("sealed body");
        let v: serde_json::Value = serde_json::from_str(&sealed).expect("json object");
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 1);
        assert_eq!(obj["sealed_request"], "c2VhbGVk");
        assert!(!sealed.contains("sealed_token"));
        assert!(!sealed.contains("hostname"));
        assert!(!sealed.contains("123"));
    }

    // Layer 1: the "import a device key" line is printed at most once per interval.
    #[test]
    fn device_key_rejection_log_is_rate_limited() {
        use super::rejection_log_due;
        use std::time::{Duration, Instant};
        let interval = Duration::from_secs(60);
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let mut last = None;
        assert!(rejection_log_due(&mut last, at(0), interval));
        // Every 30s poll inside the window stays quiet...
        assert!(!rejection_log_due(&mut last, at(30), interval));
        assert!(!rejection_log_due(&mut last, at(59), interval));
        // ...and the window restarts from the line that was printed, not from a
        // suppressed one.
        assert!(rejection_log_due(&mut last, at(60), interval));
        assert!(!rejection_log_due(&mut last, at(90), interval));
        assert!(rejection_log_due(&mut last, at(121), interval));
    }

    // Layer 1: the server's `{"error": ...}` is surfaced verbatim; anything else is
    // bounded so an intermediary's HTML page cannot flood the log.
    #[test]
    fn http_error_message_prefers_the_api_error_field() {
        use super::http_error_message;
        assert_eq!(
            http_error_message(r#"{"error":"a provisioned device key is required"}"#),
            "a provisioned device key is required"
        );
        assert_eq!(http_error_message(r#"{"other":"x"}"#), r#"{"other":"x"}"#);
        assert_eq!(http_error_message("plain text"), "plain text");
        assert_eq!(http_error_message(""), "");
        assert_eq!(http_error_message(&"x".repeat(1000)).len(), 200);
    }
}
