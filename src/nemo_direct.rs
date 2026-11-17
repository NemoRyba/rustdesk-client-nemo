//! TBFDesk direct connections: server-distributed endpoints and the optional SPA knock.
//!
//! Relay costs us ~36% of the link (measured: 7.1 of 11.1 Mbit/s on the lab WAN path),
//! so a workstation that can be reached through a port forward should be reached that
//! way. Two pieces live here:
//!
//! 1. **Endpoint distribution.** The management server pushes `nemo-direct-endpoints`
//!    inside the signed policy: `id,host:port[,knockport]` entries joined by `;`. A
//!    controller that holds an entry for the id it is dialling connects straight to it
//!    and skips the rendezvous.
//!
//! 2. **The knock.** A port forward standing open to the internet is the thing the
//!    operator wanted to avoid, so a direct endpoint may be gated by Single Packet
//!    Authorization. When `nemo-knock-enabled` is set the controller sends one
//!    fwknop-compatible (FKO 3.0.0) UDP datagram before connecting; the daemon on the
//!    edge opens the forwarded port for this source IP only, for a few seconds.
//!
//! Both are strictly ADDITIVE. No endpoint for the id, knock keys missing, the connect
//! failing, the handshake failing — every one of those falls through to the unchanged
//! hole-punch / relay path in `Client::_start_inner`. That is a hard requirement: a
//! fleet must never lose connectivity because a port forward broke.
//!
//! The SPA format was recovered from fwknop 2.6.11 and verified bidirectionally (this
//! module's `spa_matches_a_real_fwknop_packet` test decrypts a datagram fwknop itself
//! produced). Being wire-compatible means the audited `fwknopd` validates our packets;
//! we never have to be the authority on whether a knock is genuine.

use hbb_common::{anyhow::anyhow, config::Config, log, tokio, ResultType};
use std::{collections::HashMap, time::Duration};

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// `id,host:port[,knockport]` entries joined by `;`, pushed inside the signed policy.
pub const OPTION_DIRECT_ENDPOINTS: &str = "nemo-direct-endpoints";
/// Whole-attempt budget (knock delay + TCP connect + secure handshake) in ms.
pub const OPTION_DIRECT_TIMEOUT_MS: &str = "nemo-direct-timeout-ms";
/// "Y" => send an SPA packet before connecting to a direct endpoint.
pub const OPTION_KNOCK_ENABLED: &str = "nemo-knock-enabled";
/// Default UDP port the SPA goes to, when an endpoint entry carries none.
pub const OPTION_KNOCK_PORT: &str = "nemo-knock-port";
/// base64 Rijndael (AES-256) key, shared with the fwknopd on the edge. SECRET.
/// The fleet-wide fallback; a per-peer key in `nemo-knock-keys` overrides it.
pub const OPTION_KNOCK_KEY: &str = "nemo-knock-key";
/// base64 HMAC-SHA256 key, shared with the same fwknopd. SECRET.
pub const OPTION_KNOCK_HMAC_KEY: &str = "nemo-knock-hmac-key";
/// Per-peer SPA keys: `id,rijndael_b64,hmac_b64` entries joined by `;`. SECRET.
///
/// This is what gives each workstation its own knock key. The server hands a controller
/// only the rows for peers it may reach, so a key leaked from one machine opens only the
/// one port it belongs to — pc2's key can never knock pc7's edge open. A peer that has a
/// row here uses it; a peer that does not falls back to the fleet-wide
/// `nemo-knock-key`/`nemo-knock-hmac-key`, so the single-key deployment keeps working.
pub const OPTION_KNOCK_KEYS: &str = "nemo-knock-keys";
/// How long to wait after the knock before connecting.
pub const OPTION_KNOCK_DELAY_MS: &str = "nemo-knock-delay-ms";
/// Username stamped into the SPA payload (informational unless fwknopd requires it).
pub const OPTION_KNOCK_USER: &str = "nemo-knock-user";
/// Source IP to request access for. "0.0.0.0" tells fwknopd to use the packet's own
/// source address, which is what we want from behind NAT.
pub const OPTION_KNOCK_SOURCE_IP: &str = "nemo-knock-source-ip";

/// Every config key this module reads, so `nemo_management_client` can register them in
/// one place and `option_scope` cannot silently drop one.
pub const NEMO_DIRECT_SETTINGS: &[&str] = &[
    OPTION_DIRECT_ENDPOINTS,
    OPTION_DIRECT_TIMEOUT_MS,
    OPTION_KNOCK_ENABLED,
    OPTION_KNOCK_PORT,
    OPTION_KNOCK_KEY,
    OPTION_KNOCK_HMAC_KEY,
    OPTION_KNOCK_KEYS,
    OPTION_KNOCK_DELAY_MS,
    OPTION_KNOCK_USER,
    OPTION_KNOCK_SOURCE_IP,
];

const DEFAULT_KNOCK_PORT: u16 = 62201; // fwknopd's default
const DEFAULT_KNOCK_DELAY_MS: u64 = 300;
const DEFAULT_KNOCK_USER: &str = "tbfdesk";
const DEFAULT_KNOCK_SOURCE_IP: &str = "0.0.0.0";
/// Deliberately tight. A dead port forward must not add noticeable latency to a
/// connection that is about to succeed over the relay anyway. "Connect directly", which
/// has no relay to fall back to, gets a second, longer attempt (`attempt_budgets`).
const DEFAULT_DIRECT_TIMEOUT_MS: u64 = 2500;
/// fwknop refuses keys longer than this, so matching it keeps a misconfiguration a
/// local error instead of a silently-ignored datagram.
const MAX_SPA_KEY_LEN: usize = 128;

/// Where a workstation can be reached without the rendezvous, as the server described it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectEndpoint {
    pub host: String,
    pub port: u16,
    /// Per-endpoint SPA port. `None` => fall back to `nemo-knock-port`. A fleet behind
    /// several edges needs this: each site's fwknopd listens where that site's router
    /// forwards it.
    pub knock_port: Option<u16>,
}

impl DirectEndpoint {
    pub fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Parse `id,host:port[,knockport];...`. Lenient by design: one malformed entry is
/// skipped, it never discards the rest of the map, because the map arrives as one
/// policy string and a typo in a single workstation's row must not take out the fleet.
pub fn parse_endpoints(raw: &str) -> HashMap<String, DirectEndpoint> {
    let mut out = HashMap::new();
    for entry in raw.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut fields = entry.split(',').map(str::trim);
        let (Some(id), Some(addr)) = (fields.next(), fields.next()) else {
            continue;
        };
        if id.is_empty() {
            continue;
        }
        // rsplit so an IPv6 literal in brackets survives: "[2001:db8::1]:21118".
        let Some((host, port)) = addr.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if host.is_empty() || port == 0 {
            continue;
        }
        let knock_port = fields.next().and_then(|p| p.parse::<u16>().ok()).filter(|p| *p > 0);
        out.insert(
            id.to_owned(),
            DirectEndpoint {
                host: host.to_owned(),
                port,
                knock_port,
            },
        );
    }
    out
}

/// The endpoint the server published for `peer_id`, if any.
pub fn endpoint_for(peer_id: &str) -> Option<DirectEndpoint> {
    let raw = Config::get_option(OPTION_DIRECT_ENDPOINTS);
    if raw.trim().is_empty() {
        return None;
    }
    parse_endpoints(&raw).remove(peer_id)
}

/// Per-peer: "Y" => connect ONLY over the published direct endpoint, and fail with a
/// reason instead of quietly falling back to hole punch / relay.
///
/// The mirror image of the existing per-peer `force-always-relay`. Direct is already
/// automatic and silently additive, which is right as a default and useless as a test:
/// when an operator wants to know whether a port forward works, a connection that
/// succeeded over the relay anyway answers nothing. This is also what the Peers panel's
/// "Connect directly" entry sets for the one attempt.
pub const PEER_OPTION_FORCE_DIRECT: &str = "nemo-force-direct";

/// Did the operator ask for a direct-only attempt to this peer?
pub fn force_direct(peer_id: &str) -> bool {
    hbb_common::config::PeerConfig::load(peer_id)
        .options
        .get(PEER_OPTION_FORCE_DIRECT)
        .map(|v| v == "Y")
        .unwrap_or(false)
}

/// Read the flag and CLEAR it, at the start of one connection attempt.
///
/// One-shot by construction: "Connect directly" answers a question about this attempt
/// ("does the forward work?"), so leaving the flag set would silently turn the peer into
/// a direct-only peer and break the next ordinary connect when the forward goes away.
/// Consuming it here rather than in the UI means it is cleared whether the attempt
/// succeeds, fails or the window is closed mid-connect.
pub fn take_force_direct(peer_id: &str) -> bool {
    let mut c = hbb_common::config::PeerConfig::load(peer_id);
    if c.options.remove(PEER_OPTION_FORCE_DIRECT).is_none() {
        return false;
    }
    c.store(peer_id);
    true
}

/// Does this client currently hold a per-peer SPA key for `peer_id` (as opposed to
/// falling back to the fleet-wide key)? For the UI's knock status line.
pub fn has_peer_knock_key(peer_id: &str) -> bool {
    per_peer_knock_key(peer_id).is_some()
}

/// The SPA (knock) port that a connection to `peer_id` would use, or `None` when knocking
/// is off on this client. The per-endpoint knock port wins, else the global one. For the
/// UI only; the real send path computes the same value in `knock_config_for`.
pub fn knock_port_for(peer_id: &str) -> Option<u16> {
    if Config::get_option(OPTION_KNOCK_ENABLED) != "Y" {
        return None;
    }
    let global = Config::get_option(OPTION_KNOCK_PORT)
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_KNOCK_PORT);
    Some(endpoint_for(peer_id).and_then(|e| e.knock_port).unwrap_or(global))
}

/// The endpoint for this id as plain `host:port`, for the UI. Empty when the management
/// server has not published one, which is exactly when direct access is NOT possible.
pub fn endpoint_label(peer_id: &str) -> String {
    endpoint_for(peer_id)
        .map(|e| e.target())
        .unwrap_or_default()
}

/// Every id the server has published an endpoint for. The address book marks these, so
/// an operator can see at a glance which machines cost a third of the link and which do
/// not.
pub fn direct_capable_ids() -> Vec<String> {
    let raw = Config::get_option(OPTION_DIRECT_ENDPOINTS);
    if raw.trim().is_empty() {
        return Vec::new();
    }
    let mut ids: Vec<String> = parse_endpoints(&raw).into_keys().collect();
    ids.sort();
    ids
}

/// Why there is no direct endpoint for `peer_id`, in words a log reader can act on.
///
/// The direct attempt used to return silently when no endpoint was known, so the
/// session log of a controller that never received one said nothing about direct at
/// all -- indistinguishable from an old build, or from the feature being off. The
/// three causes need three different fixes (turn the managed poll on, find out why the
/// poll never got a policy, publish the endpoint in the dashboard), so name which one
/// it is.
pub fn why_no_endpoint(peer_id: &str) -> String {
    // The server also withholds a set endpoint, deliberately, so say so: a blocked peer's
    // address is never handed out, and a controller only learns endpoints of targets its
    // own outbound policy allows.
    const WITHHELD: &str = " (if it is set, the server withholds it: the peer is blocked, \
                            or it is not in this client's allowed outbound targets)";
    if Config::get_option("nemo-management-enabled") != "Y" {
        return "the managed policy poll is OFF on this client, so it never receives \
                endpoints (import the setup string again, or enable it)"
            .to_owned();
    }
    let issued = Config::get_option("nemo-policy-issued-ts");
    if issued.trim().is_empty() {
        return "this client has not received a policy from the management server yet \
                (check that it can reach the API and that its device key is approved)"
            .to_owned();
    }
    let ids = direct_capable_ids();
    let known: Vec<&String> = ids.iter().filter(|i| i.as_str() != peer_id).collect();
    if known.is_empty() {
        format!(
            "the last policy (issued {issued}) published no direct endpoints at all; \
             set 'Reachable at' for {peer_id} in the dashboard{WITHHELD}"
        )
    } else {
        format!(
            "the last policy (issued {issued}) has endpoints for {} other peer(s) ({}) \
             but none for {peer_id}; set 'Reachable at' for it in the dashboard{WITHHELD}",
            known.len(),
            known
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// How often the same (peer, outcome) is reported again. A TCP tunnel opens one
/// connection per forwarded socket, a browser behind one opens dozens a minute; the
/// server needs to know that it works, not to count every socket.
const REPORT_REPEAT_AFTER: Duration = Duration::from_secs(600);

/// Tell the management server about one attempt at a published direct endpoint.
///
/// A direct session never touches the rendezvous, so this report is the server's only
/// record of it -- without it the dashboard showed no direct session at all, and a
/// failed attempt left no trace anywhere but this machine's log. The controller sends
/// it because only the controller knows the outcome: the target never sees an attempt
/// that failed on the way.
///
/// Sparse by construction: at most one small HTTPS POST per attempt, never during a
/// session, sent from its own thread so the connection never waits for it, and the
/// same (peer, result) at most once per REPORT_REPEAT_AFTER. Signed with the device key
/// like every client audit; no key or no management server = nothing is sent.
/// `result`: "established" | "failed" | "not-tried".
pub fn report_attempt(peer_id: &str, endpoint: &str, result: &str, ms: Option<u128>, detail: &str) {
    lazy_static::lazy_static! {
        static ref LAST: std::sync::Mutex<HashMap<(String, String), std::time::Instant>> =
            Default::default();
    }
    if !due_for_report(&mut LAST.lock().unwrap(), peer_id, result, std::time::Instant::now()) {
        return;
    }
    let url = crate::common::get_audit_server(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
        "direct".to_owned(),
    );
    if url.is_empty() {
        return;
    }
    let mut body = serde_json::json!({
        "peer": peer_id,
        "endpoint": endpoint,
        "result": result,
        "detail": detail.chars().take(200).collect::<String>(),
        "version": crate::VERSION,
    });
    if let Some(ms) = ms {
        body["ms"] = serde_json::json!(ms as u64);
    }
    std::thread::spawn(move || post_report(url, body));
}

/// True (and remembered) unless the same (peer, result) was reported within
/// REPORT_REPEAT_AFTER. A different outcome is always reported at once.
fn due_for_report(
    last: &mut HashMap<(String, String), std::time::Instant>,
    peer_id: &str,
    result: &str,
    now: std::time::Instant,
) -> bool {
    let key = (peer_id.to_owned(), result.to_owned());
    if matches!(last.get(&key), Some(t) if now.duration_since(*t) < REPORT_REPEAT_AFTER) {
        return false;
    }
    last.insert(key, now);
    true
}

#[tokio::main(flavor = "current_thread")]
async fn post_report(url: String, mut body: serde_json::Value) {
    let me = Config::get_id();
    let (pk, sig) = crate::common::nemo_device_sign("nemo-audit", &me);
    if pk.is_empty() {
        log::debug!("direct report not sent: no device key on this machine");
        return;
    }
    body["id"] = serde_json::json!(me);
    body["device_key_pub"] = serde_json::json!(pk);
    body["device_key_sig"] = serde_json::json!(sig);
    match crate::post_request(url.clone(), body.to_string(), "").await {
        Ok(text) if text.contains("\"error\"") => {
            log::warn!("direct report to {} refused: {:.200}", url, text)
        }
        Ok(_) => {}
        Err(e) => log::debug!("direct report to {} not delivered: {}", url, e),
    }
}

pub fn direct_timeout() -> Duration {
    let ms = Config::get_option(OPTION_DIRECT_TIMEOUT_MS)
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|ms| *ms > 0)
        .unwrap_or(DEFAULT_DIRECT_TIMEOUT_MS);
    Duration::from_millis(ms)
}

/// Floor for the second "Connect directly" attempt. A chosen value, not a measured one:
/// the field case behind it needed about 1 s on a good attempt (1.05 s), so a 2.5 s
/// budget left little room for a single lost packet during setup or a slow knock gate.
/// 6 s gives the retry that room and still ends the "Connecting" wait in under 10 s.
const FORCED_RETRY_MIN_BUDGET_MS: u64 = 6000;
/// Ceiling for the second attempt, so a large policy budget cannot hold the
/// "Connecting" dialog open for minutes.
const FORCED_RETRY_MAX_BUDGET_MS: u64 = 20_000;

/// The budget of each attempt at a direct endpoint, in order.
///
/// An ordinary connection gets ONE attempt with the policy budget. When it fails, the
/// session continues over hole punch / relay, and every extra second here is a second a
/// broken port forward adds to that fallback ("deliberately tight", above).
///
/// "Connect directly" has no fallback: its failure is the answer the user reads. So a
/// failure that a second try can plausibly fix (see [`DirectFailure::retryable`]) gets
/// one more attempt, with twice the budget (at least 6 s) and a fresh knock, before it
/// is reported. The field report behind this: five "Direct connection ... failed"
/// dialogs in a row, and a little later the same endpoint connected in 1.05 s. Why those
/// five failed is not known (the log could not say which phase failed); the retry covers
/// the transient causes, and the per-phase reason now names the rest.
pub fn attempt_budgets(budget: Duration, force_direct: bool) -> Vec<Duration> {
    if !force_direct {
        return vec![budget];
    }
    let retry = (budget * 2)
        .clamp(
            Duration::from_millis(FORCED_RETRY_MIN_BUDGET_MS),
            Duration::from_millis(FORCED_RETRY_MAX_BUDGET_MS),
        )
        .max(budget);
    vec![budget, retry]
}

/// Is knocking switched on for this client, whether or not it has a usable key?
pub fn knock_enabled() -> bool {
    Config::get_option(OPTION_KNOCK_ENABLED) == "Y"
}

/// What the knock did before one attempt. The knock is a UDP datagram with no answer,
/// so "sent" is all this client can ever know; whether the daemon accepted it shows only
/// in the TCP connect that follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnockState {
    /// Knocking is off on this client.
    Off,
    /// One SPA datagram went out to this UDP port.
    Sent(u16),
    /// Knocking is on, but nothing went out, for this reason.
    NotSent(String),
}

impl KnockState {
    fn note(&self) -> String {
        match self {
            KnockState::Off => String::new(),
            KnockState::Sent(port) => format!(" (after a knock to udp/{port})"),
            KnockState::NotSent(why) => {
                format!(" (knocking is on, but no knock was sent: {why})")
            }
        }
    }
}

/// Why one attempt at a direct endpoint failed, by the phase it failed in.
///
/// Each one has a different fix: a dropped SYN points at the forward, a firewall or the
/// knock gate; a refusal points at the router or a stopped service; a closed or foreign
/// handshake points at where the forward lands; a key mismatch is a security finding.
/// The dialog used to say "see the log" for all of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectFailure {
    /// No answer at all to the TCP connect within `ms`: something drops it silently.
    ConnectTimeout { ms: u64 },
    /// The TCP connect was refused: something answered with a reset.
    Refused,
    /// Any other TCP-level failure (unreachable network, a name with no address, ...).
    ConnectError(String),
    /// TCP came up after `tcp_ms`, but the TBFDesk handshake did not finish within `ms`.
    HandshakeTimeout { tcp_ms: u64, ms: u64 },
    /// Accepted, then closed or reset before the handshake finished.
    Closed(String),
    /// Something answered, but not with a TBFDesk handshake.
    NotTbfdesk(String),
    /// A TBFDesk peer answered, but this client holds no server key for the id it claims.
    NoServerKey(String),
    /// The peer could not prove it is the requested id (bad signature, or another id).
    KeyMismatch(String),
    /// Anything else, including a knock that left no time to connect.
    Other(String),
}

impl DirectFailure {
    /// One line for the log and the server report. Leads with the class, because the
    /// server keeps only the first 200 characters.
    pub fn summary(&self) -> String {
        match self {
            DirectFailure::ConnectTimeout { ms } => {
                format!("connect timeout: no answer to the TCP connect within {ms} ms")
            }
            DirectFailure::Refused => "refused: the TCP connect was refused (nothing accepts \
                                       connections on that port, or a router answers it itself)"
                .to_owned(),
            DirectFailure::ConnectError(e) => format!("connect error: {e}"),
            DirectFailure::HandshakeTimeout { tcp_ms, ms } => format!(
                "handshake timeout: TCP up after {tcp_ms} ms, but no TBFDesk handshake within \
                 {ms} ms"
            ),
            DirectFailure::Closed(e) => format!("closed during the handshake: {e}"),
            DirectFailure::NotTbfdesk(e) => format!("not TBFDesk: {e}"),
            DirectFailure::NoServerKey(e) => format!("no server key: {e}"),
            DirectFailure::KeyMismatch(e) => format!("key mismatch: {e}"),
            DirectFailure::Other(e) => format!("failed: {e}"),
        }
    }

    /// May a second "Connect directly" attempt plausibly succeed where this one failed?
    ///
    /// Timeouts: yes. A lost packet, a slow path or a gate that opened late are exactly
    /// what a second try with a longer budget fixes. A refusal: only when a knock is
    /// involved, because a knock-gated port can answer with a reset until the daemon has
    /// opened it (lab: "connection refused" 0.3 s after the knock); a fresh knock and a
    /// second connect may find it open. Everything else names something that waiting does
    /// not change, and an identity failure must never be retried until it happens to pass.
    pub fn retryable(&self, knock: &KnockState) -> bool {
        match self {
            DirectFailure::ConnectTimeout { .. } | DirectFailure::HandshakeTimeout { .. } => true,
            DirectFailure::Refused => *knock != KnockState::Off,
            _ => false,
        }
    }
}

/// One failed attempt: why, what the knock did, and how long the attempt took.
#[derive(Clone, Debug)]
pub struct DirectAttemptError {
    pub failure: DirectFailure,
    pub knock: KnockState,
    pub elapsed_ms: u64,
}

impl DirectAttemptError {
    pub fn summary(&self) -> String {
        format!("{}{}", self.failure.summary(), self.knock.note())
    }
}

/// Name a failed TCP connect from the text hbb_common's `FramedStream::new` (tcp.rs)
/// builds: "<addr>: connection refused" and "<addr>: timed out after N ms" are its
/// fixed words for those two cases (English on every OS), anything else is the OS error.
pub fn classify_connect_error(text: &str, waited_ms: u64) -> DirectFailure {
    let lower = text.to_lowercase();
    if lower.contains("connection refused") {
        DirectFailure::Refused
    } else if lower.contains("timed out") {
        DirectFailure::ConnectTimeout { ms: waited_ms }
    } else {
        DirectFailure::ConnectError(text.to_owned())
    }
}

/// What `Client::secure_connection_direct` refused, for [`DirectHandshakeError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRefusal {
    Closed,
    NotTbfdesk,
    NoServerKey,
    KeyMismatch,
}

/// A refusal from `Client::secure_connection_direct`, typed so the direct path can name
/// it without matching its wording. It displays exactly the text the plain message had,
/// so the other callers of `secure_connection` log and show what they did before.
#[derive(Debug)]
pub struct DirectHandshakeError {
    pub kind: HandshakeRefusal,
    pub text: String,
}

impl std::fmt::Display for DirectHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for DirectHandshakeError {}

pub fn handshake_refusal(kind: HandshakeRefusal, text: impl Into<String>) -> hbb_common::anyhow::Error {
    hbb_common::anyhow::Error::new(DirectHandshakeError {
        kind,
        text: text.into(),
    })
}

/// Name a failed direct handshake: a typed refusal from `secure_connection_direct`, a
/// socket the peer closed or reset, or anything else as it was worded.
pub fn classify_handshake_error(e: &hbb_common::anyhow::Error) -> DirectFailure {
    let text = e.to_string();
    if let Some(refusal) = e.downcast_ref::<DirectHandshakeError>() {
        return match refusal.kind {
            HandshakeRefusal::Closed => DirectFailure::Closed(text),
            HandshakeRefusal::NotTbfdesk => DirectFailure::NotTbfdesk(text),
            HandshakeRefusal::NoServerKey => DirectFailure::NoServerKey(text),
            HandshakeRefusal::KeyMismatch => DirectFailure::KeyMismatch(text),
        };
    }
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        use std::io::ErrorKind::*;
        if matches!(
            io.kind(),
            ConnectionReset | ConnectionAborted | UnexpectedEof | BrokenPipe
        ) {
            return DirectFailure::Closed(text);
        }
    }
    DirectFailure::Other(text)
}

// The "Connect directly" failure texts, one per reason. Each is a translation key with
// a single `{}` (lang.rs fills only the first placeholder): the peer id, the endpoint and
// the attempt times go into it as "id (host:port, 2500 + 6000 ms)", which reads the same
// in every language. German for every one is in de.rs; lang.rs tests that it is there.
// All start with crate::client::FORCED_DIRECT_FAILED, which keeps them out of the
// automatic retry (check_if_retry) -- that retry would end on the relay.
const FD_TIMEOUT: &str = "Direct connection to {} failed: no answer to the TCP connection request. A port forward, firewall or router on the way drops it, or the computer is switched off. The relay was NOT used because you asked for a direct connection.";
const FD_TIMEOUT_KNOCKED: &str = "Direct connection to {} failed: a knock was sent, but the TCP connection request got no answer. Either the knock was not accepted (wrong knock key, or this computer's clock is wrong), or a port forward or firewall drops the connection. The relay was NOT used because you asked for a direct connection.";
const FD_REFUSED: &str = "Direct connection to {} failed: the connection was refused. Something at that address answered, but nothing accepts connections on that port: TBFDesk is not running on the computer, or the router answers the port itself instead of forwarding it. The relay was NOT used because you asked for a direct connection.";
const FD_REFUSED_KNOCKED: &str = "Direct connection to {} failed: a knock was sent, but the connection was refused. Probably the knock was not accepted (wrong knock key, or this computer's clock is wrong) and the port stayed closed, or nothing accepts connections behind the port forward. The relay was NOT used because you asked for a direct connection.";
const FD_KNOCK_NOT_SENT: &str = "Direct connection to {} failed: knocking is switched on, but this computer could not send the knock (no usable knock key, or sending failed), and the connection did not get through. The relay was NOT used because you asked for a direct connection.";
const FD_HANDSHAKE_TIMEOUT: &str = "Direct connection to {} failed: the TCP connection was established, but the TBFDesk handshake did not finish in time. The path is very slow, or the port forward reaches something that is not TBFDesk. The relay was NOT used because you asked for a direct connection.";
const FD_CLOSED: &str = "Direct connection to {} failed: the connection was accepted and then closed before the TBFDesk handshake. The port forward probably reaches a computer or port where TBFDesk is not answering, or the computer dropped the connection. The relay was NOT used because you asked for a direct connection.";
const FD_NOT_TBFDESK: &str = "Direct connection to {} failed: the endpoint answered, but not as TBFDesk. The port forward reaches a different service, not the computer. The relay was NOT used because you asked for a direct connection.";
const FD_NO_SERVER_KEY: &str = "Direct connection to {} failed: a TBFDesk computer answered, but this client holds no key from your server for it. Wait for the next policy update, or check in the dashboard that the port forward points at this computer. The relay was NOT used because you asked for a direct connection.";
const FD_KEY_MISMATCH: &str = "Direct connection to {} failed: the computer at that address could not prove that it is this computer (its identity does not match the key your server published). Not retried: the port forward may reach a different computer, or someone is intercepting the connection. The relay was NOT used because you asked for a direct connection.";
const FD_ERROR: &str = "Direct connection to {} failed with the error shown after the address. The relay was NOT used because you asked for a direct connection.";

/// Every "Connect directly" failure text that [`DirectFailed::user_message`] can
/// produce, for the translation test in lang.rs.
pub const FORCED_DIRECT_REASON_KEYS: &[&str] = &[
    FD_TIMEOUT,
    FD_TIMEOUT_KNOCKED,
    FD_REFUSED,
    FD_REFUSED_KNOCKED,
    FD_KNOCK_NOT_SENT,
    FD_HANDSHAKE_TIMEOUT,
    FD_CLOSED,
    FD_NOT_TBFDESK,
    FD_NO_SERVER_KEY,
    FD_KEY_MISMATCH,
    FD_ERROR,
];

fn reason_key(failure: &DirectFailure, knock: &KnockState) -> &'static str {
    match (failure, knock) {
        (DirectFailure::ConnectTimeout { .. } | DirectFailure::Refused, KnockState::NotSent(_)) => {
            FD_KNOCK_NOT_SENT
        }
        (DirectFailure::ConnectTimeout { .. }, KnockState::Sent(_)) => FD_TIMEOUT_KNOCKED,
        (DirectFailure::ConnectTimeout { .. }, KnockState::Off) => FD_TIMEOUT,
        (DirectFailure::Refused, KnockState::Sent(_)) => FD_REFUSED_KNOCKED,
        (DirectFailure::Refused, KnockState::Off) => FD_REFUSED,
        (DirectFailure::HandshakeTimeout { .. }, _) => FD_HANDSHAKE_TIMEOUT,
        (DirectFailure::Closed(_), _) => FD_CLOSED,
        (DirectFailure::NotTbfdesk(_), _) => FD_NOT_TBFDESK,
        (DirectFailure::NoServerKey(_), _) => FD_NO_SERVER_KEY,
        (DirectFailure::KeyMismatch(_), _) => FD_KEY_MISMATCH,
        (DirectFailure::ConnectError(_) | DirectFailure::Other(_), _) => FD_ERROR,
    }
}

/// Every failed attempt at one endpoint, in order: what "Connect directly" shows and
/// what the management server is told.
#[derive(Clone, Debug)]
pub struct DirectFailed {
    pub endpoint: String,
    pub attempts: Vec<DirectAttemptError>,
}

impl DirectFailed {
    /// For the server report: the final reason first, so it survives the server's
    /// 200-character cut, then what the earlier attempts ran into.
    pub fn detail(&self) -> String {
        let n = self.attempts.len();
        let Some(last) = self.attempts.last() else {
            return String::new();
        };
        if n == 1 {
            return last.summary();
        }
        format!(
            "{} [attempt {n} of {n}; before: {}]",
            last.summary(),
            self.attempts[..n - 1]
                .iter()
                .map(|a| a.summary())
                .collect::<Vec<_>>()
                .join("; ")
        )
    }

    /// For a connection that succeeded after these failures (empty when it is the first
    /// attempt that succeeded).
    pub fn earlier(&self) -> String {
        if self.attempts.is_empty() {
            return String::new();
        }
        format!(
            "after {} failed attempt(s): {}",
            self.attempts.len(),
            self.attempts
                .iter()
                .map(|a| a.summary())
                .collect::<Vec<_>>()
                .join("; ")
        )
    }

    /// The text "Connect directly" fails with: the last attempt's reason, translated,
    /// with the peer, the endpoint and every attempt's duration in its one placeholder.
    pub fn user_message(&self, peer_id: &str) -> String {
        let times = self
            .attempts
            .iter()
            .map(|a| a.elapsed_ms.to_string())
            .collect::<Vec<_>>()
            .join(" + ");
        let mut value = format!("{} ({}", peer_id, self.endpoint);
        if !times.is_empty() {
            value.push_str(&format!(", {times} ms"));
        }
        let key = match self.attempts.last() {
            Some(last) => {
                if let DirectFailure::ConnectError(e) | DirectFailure::Other(e) = &last.failure {
                    value.push_str("; ");
                    value.push_str(e);
                }
                reason_key(&last.failure, &last.knock)
            }
            None => FD_ERROR,
        };
        value.push(')');
        // lang.rs takes the text between the first `{` and the next `}` as the value.
        let value = value.replace('{', "(").replace('}', ")");
        key.replacen("{}", &format!("{{{value}}}"), 1)
    }
}

/// Everything needed to build and send one SPA packet.
#[derive(Clone, Debug)]
pub struct KnockConfig {
    pub port: u16,
    pub key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub delay: Duration,
    pub user: String,
    pub source_ip: String,
}

/// The knock settings for a connection to `peer_id`, or `None` when knocking is off or
/// unusable.
///
/// The SPA keys come from the peer's own row in `nemo-knock-keys` when it has one, and
/// otherwise from the fleet-wide `nemo-knock-key`/`nemo-knock-hmac-key`. That split is
/// the whole point of per-peer keys: with a row per workstation, a key leaked from one
/// machine opens only that machine's port; without any rows the client behaves exactly
/// as before. When a peer has its own key the global key need not be set at all, so a
/// deployment can distribute *only* per-peer keys.
///
/// A half-configured knock (enabled, no usable key for this peer and no global key)
/// returns `None` and logs: the connection then goes out WITHOUT a knock, which either
/// succeeds (the port was never gated) or fails and falls back to the relay. Refusing to
/// connect would be the wrong call — the knock is a hardening layer over a port forward,
/// not an authentication boundary for the session itself. That boundary is the Ed25519
/// handshake, which runs either way.
pub fn knock_config_for(peer_id: &str) -> Option<KnockConfig> {
    if Config::get_option(OPTION_KNOCK_ENABLED) != "Y" {
        return None;
    }
    let (key, hmac_key) = match per_peer_knock_key(peer_id) {
        Some(pair) => pair,
        // No per-peer key: fall back to the fleet-wide pair, both required.
        None => (
            decode_spa_key(&Config::get_option(OPTION_KNOCK_KEY), OPTION_KNOCK_KEY)?,
            decode_spa_key(
                &Config::get_option(OPTION_KNOCK_HMAC_KEY),
                OPTION_KNOCK_HMAC_KEY,
            )?,
        ),
    };
    let port = Config::get_option(OPTION_KNOCK_PORT)
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_KNOCK_PORT);
    let delay = Duration::from_millis(
        Config::get_option(OPTION_KNOCK_DELAY_MS)
            .trim()
            .parse::<u64>()
            .unwrap_or(DEFAULT_KNOCK_DELAY_MS),
    );
    let user = non_empty(Config::get_option(OPTION_KNOCK_USER), DEFAULT_KNOCK_USER);
    let source_ip = non_empty(
        Config::get_option(OPTION_KNOCK_SOURCE_IP),
        DEFAULT_KNOCK_SOURCE_IP,
    );
    Some(KnockConfig {
        port,
        key,
        hmac_key,
        delay,
        user,
        source_ip,
    })
}

/// The fleet-wide knock settings, with no per-peer key override. Equivalent to
/// `knock_config_for("")`: an empty id never matches a row in `nemo-knock-keys`.
pub fn knock_config() -> Option<KnockConfig> {
    knock_config_for("")
}

/// The (rijndael, hmac) SPA key pair the server published for `peer_id` in
/// `nemo-knock-keys`, or `None` when that map is empty, has no row for this peer, or the
/// row's keys do not decode. A row that fails to decode falls through to the global key
/// rather than disabling the knock, which matches the lenient handling everywhere else
/// on this path: a bad row must never cost a reachable workstation its connection.
fn per_peer_knock_key(peer_id: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    if peer_id.is_empty() {
        return None;
    }
    let raw = Config::get_option(OPTION_KNOCK_KEYS);
    if raw.trim().is_empty() {
        return None;
    }
    parse_knock_keys(&raw).remove(peer_id)
}

/// Parse `id,rijndael_b64,hmac_b64;...` into a per-peer SPA key map. Lenient by design,
/// exactly like [`parse_endpoints`]: one malformed or undecodable row is skipped and
/// never discards the rest, because the whole map arrives as a single policy string and
/// a typo in one workstation's row must not take out the fleet.
pub fn parse_knock_keys(raw: &str) -> HashMap<String, (Vec<u8>, Vec<u8>)> {
    let mut out = HashMap::new();
    for entry in raw.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut fields = entry.split(',').map(str::trim);
        let (Some(id), Some(k), Some(h)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        if id.is_empty() {
            continue;
        }
        let (Some(key), Some(hmac_key)) = (
            decode_spa_key(k, OPTION_KNOCK_KEYS),
            decode_spa_key(h, OPTION_KNOCK_KEYS),
        ) else {
            continue;
        };
        out.insert(id.to_owned(), (key, hmac_key));
    }
    out
}

fn non_empty(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value.trim().to_owned()
    }
}

fn decode_spa_key(raw: &str, which: &str) -> Option<Vec<u8>> {
    let raw = raw.trim();
    if raw.is_empty() {
        log::warn!(
            "TBFDesk knock: {} is enabled but {} is not set; connecting without a knock",
            OPTION_KNOCK_ENABLED,
            which
        );
        return None;
    }
    match crate::common::decode64(raw) {
        Ok(key) if !key.is_empty() && key.len() <= MAX_SPA_KEY_LEN => Some(key),
        Ok(key) => {
            log::warn!(
                "TBFDesk knock: {} decodes to {} bytes (expected 1..={}); connecting without a knock",
                which,
                key.len(),
                MAX_SPA_KEY_LEN
            );
            None
        }
        Err(e) => {
            log::warn!(
                "TBFDesk knock: {} is not valid base64 ({}); connecting without a knock",
                which,
                e
            );
            None
        }
    }
}

/// base64 with the padding removed, which is how every field inside an SPA packet and
/// the packet itself are encoded.
fn b64_stripped<T: AsRef<[u8]>>(data: T) -> String {
    crate::common::encode64(data)
        .trim_end_matches('=')
        .to_owned()
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and a single iteration — the derivation
/// `openssl enc -aes-256-cbc` uses, and therefore the one fwknop's Rijndael mode uses.
fn evp_bytes_to_key(password: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut material = Vec::with_capacity(48);
    let mut block: Vec<u8> = Vec::new();
    while material.len() < 48 {
        let mut hasher = Md5::new();
        hasher.update(&block);
        hasher.update(password);
        hasher.update(salt);
        block = hasher.finalize().to_vec();
        material.extend_from_slice(&block);
    }
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&material[..32]);
    iv.copy_from_slice(&material[32..48]);
    (key, iv)
}

/// FKO message type 1: an access request.
const FKO_ACCESS_MSG: u8 = 1;
const FKO_VERSION: &str = "3.0.0";
/// base64("Salted__"), which fwknop strips from the wire and re-adds before decrypting.
const SALTED_B64_PREFIX: &str = "U2FsdGVkX1";

/// Build one SPA packet. `rand16` and `salt` are parameters rather than generated here
/// so the format is testable against a datagram fwknop produced.
fn build_spa_packet(
    cfg: &KnockConfig,
    access: &str,
    timestamp: u64,
    rand16: &str,
    salt: &[u8; 8],
) -> ResultType<String> {
    // <rand>:<b64 user>:<ts>:<version>:<type>:<b64 access>, then its own SHA-256.
    let mut plaintext = format!(
        "{}:{}:{}:{}:{}:{}",
        rand16,
        b64_stripped(&cfg.user),
        timestamp,
        FKO_VERSION,
        FKO_ACCESS_MSG,
        b64_stripped(access),
    );
    let digest = Sha256::digest(plaintext.as_bytes());
    plaintext.push(':');
    plaintext.push_str(&b64_stripped(digest));

    let (key, iv) = evp_bytes_to_key(&cfg.key, salt);
    let pt = plaintext.as_bytes();
    let mut buf = vec![0u8; pt.len() + 16];
    buf[..pt.len()].copy_from_slice(pt);
    let ciphertext = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt.len())
        .map_err(|e| anyhow!("SPA encryption failed: {e}"))?;

    // OpenSSL's salted envelope, which is what fwknop encodes.
    let mut raw = Vec::with_capacity(16 + ciphertext.len());
    raw.extend_from_slice(b"Salted__");
    raw.extend_from_slice(salt);
    raw.extend_from_slice(ciphertext);
    let encoded = b64_stripped(&raw);

    // fwknop authenticates the encoded form INCLUDING the "Salted__" prefix, then drops
    // the prefix on the wire; the daemon re-adds it before checking. So the HMAC input
    // is not the string we transmit.
    let mut mac = HmacSha256::new_from_slice(&cfg.hmac_key)
        .map_err(|e| anyhow!("SPA HMAC key rejected: {e}"))?;
    mac.update(encoded.as_bytes());
    let tag = mac.finalize().into_bytes();

    let body = encoded
        .strip_prefix(SALTED_B64_PREFIX)
        .ok_or_else(|| anyhow!("SPA ciphertext is missing its salted prefix"))?;
    Ok(format!("{}{}", body, b64_stripped(tag)))
}

/// 16 decimal digits, the replay-cache nonce fwknop puts at the head of every packet.
fn random_rand16() -> String {
    format!(
        "{:016}",
        hbb_common::rand::random::<u64>() % 10_000_000_000_000_000
    )
}

/// Send one SPA datagram asking the edge to open `tcp/<port>` on `host` for us.
///
/// Returns once the datagram is out and `cfg.delay` has elapsed. UDP, so there is no
/// acknowledgement to wait for and no way to know the daemon liked it — the TCP connect
/// that follows is the only evidence, and its failure is already a fallback to relay.
pub async fn knock(host: &str, port: u16, cfg: &KnockConfig) -> ResultType<()> {
    let access = format!("{},tcp/{}", cfg.source_ip, port);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&hbb_common::rand::random::<u64>().to_le_bytes());
    let packet = build_spa_packet(cfg, &access, timestamp, &random_rand16(), &salt)?;

    // An IPv6 endpoint is stored bracketed for host:port parsing; tokio's resolver
    // wants the bare address.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let socket = hbb_common::tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let sent = socket.send_to(packet.as_bytes(), (host, cfg.port)).await?;
    log::info!(
        "TBFDesk knock: sent {} byte SPA to {}:{} requesting {}",
        sent,
        host,
        cfg.port,
        access
    );
    if !cfg.delay.is_zero() {
        hbb_common::tokio::time::sleep(cfg.delay).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnel opening a connection per socket must not turn into a report per socket,
    /// but a change of outcome must reach the server at once.
    #[test]
    fn direct_reports_are_sparse_but_a_change_of_outcome_is_not_held_back() {
        let mut last = HashMap::new();
        let t0 = std::time::Instant::now();
        assert!(due_for_report(&mut last, "352069946", "established", t0));
        for s in [1, 30, 599] {
            let t = t0 + Duration::from_secs(s);
            assert!(!due_for_report(&mut last, "352069946", "established", t), "repeat at {s}s");
        }
        // A failure right after a success is news.
        assert!(due_for_report(&mut last, "352069946", "failed", t0 + Duration::from_secs(2)));
        // Another peer is independent.
        assert!(due_for_report(&mut last, "91090423", "established", t0 + Duration::from_secs(2)));
        // After the window the same outcome is reported again.
        assert!(due_for_report(&mut last, "352069946", "established", t0 + REPORT_REPEAT_AFTER));
    }

    /// An ordinary connection keeps its one short attempt (its fallback is the relay);
    /// "Connect directly" gets a second, longer one, bounded either way.
    #[test]
    fn only_connect_directly_gets_a_second_longer_attempt() {
        let ms = Duration::from_millis;
        assert_eq!(attempt_budgets(ms(2500), false), vec![ms(2500)]);
        assert_eq!(attempt_budgets(ms(2500), true), vec![ms(2500), ms(6000)]);
        assert_eq!(attempt_budgets(ms(5000), true), vec![ms(5000), ms(10_000)]);
        assert_eq!(attempt_budgets(ms(15_000), true), vec![ms(15_000), ms(20_000)]);
        // A budget above the ceiling is never shortened for the retry.
        assert_eq!(attempt_budgets(ms(30_000), true), vec![ms(30_000), ms(30_000)]);
    }

    /// The connect classifier reads hbb_common's fixed words (tcp.rs, FramedStream::new
    /// and connect_failure). If those change, this is where it shows.
    #[test]
    fn connect_failures_are_named_from_hbb_commons_words() {
        assert_eq!(
            classify_connect_error(
                "Failed to connect to 85.126.226.2:21010 (85.126.226.2:21010: connection refused)",
                2200
            ),
            DirectFailure::Refused
        );
        assert_eq!(
            classify_connect_error(
                "Failed to connect to 10.0.2.2:21218 (10.0.2.2:21218: timed out after 2200 ms)",
                2200
            ),
            DirectFailure::ConnectTimeout { ms: 2200 }
        );
        let other = "Failed to connect to 10.0.2.2:21218 (10.0.2.2:21218: Network is unreachable (os error 101))";
        assert_eq!(
            classify_connect_error(other, 2200),
            DirectFailure::ConnectError(other.to_owned())
        );
    }

    /// The handshake classifier reads the typed refusal, not the wording, and the typed
    /// refusal still displays the old text for the callers that only log it.
    #[test]
    fn handshake_refusals_keep_their_text_and_gain_a_kind() {
        let e = handshake_refusal(HandshakeRefusal::KeyMismatch, "direct peer id 1 != requested 2");
        assert_eq!(e.to_string(), "direct peer id 1 != requested 2");
        assert_eq!(
            classify_handshake_error(&e),
            DirectFailure::KeyMismatch("direct peer id 1 != requested 2".to_owned())
        );
        let e = handshake_refusal(HandshakeRefusal::Closed, "closed");
        assert_eq!(classify_handshake_error(&e), DirectFailure::Closed("closed".to_owned()));
        let reset: hbb_common::anyhow::Error =
            std::io::Error::from(std::io::ErrorKind::ConnectionReset).into();
        assert!(matches!(classify_handshake_error(&reset), DirectFailure::Closed(_)));
        let other = hbb_common::anyhow::anyhow!("something else");
        assert_eq!(
            classify_handshake_error(&other),
            DirectFailure::Other("something else".to_owned())
        );
    }

    /// Retry what waiting can fix; never an identity failure.
    #[test]
    fn only_failures_a_second_try_can_fix_are_retried() {
        let off = KnockState::Off;
        let sent = KnockState::Sent(62201);
        assert!(DirectFailure::ConnectTimeout { ms: 1 }.retryable(&off));
        assert!(DirectFailure::HandshakeTimeout { tcp_ms: 1, ms: 1 }.retryable(&off));
        assert!(!DirectFailure::Refused.retryable(&off), "nothing listens: waiting does not help");
        assert!(DirectFailure::Refused.retryable(&sent), "a knock-gated port may open late");
        for f in [
            DirectFailure::KeyMismatch(String::new()),
            DirectFailure::NoServerKey(String::new()),
            DirectFailure::NotTbfdesk(String::new()),
            DirectFailure::Closed(String::new()),
            DirectFailure::ConnectError(String::new()),
            DirectFailure::Other(String::new()),
        ] {
            assert!(!f.retryable(&sent), "{f:?}");
        }
    }

    /// The dialog text: the FORCED_DIRECT_FAILED prefix (keeps it out of the automatic
    /// retry), one placeholder holding id, endpoint and attempt times, the reason of the
    /// LAST attempt, and nothing that could end the placeholder early.
    #[test]
    fn the_dialog_names_the_reason_of_the_last_attempt() {
        let attempt = |failure, knock, elapsed_ms| DirectAttemptError {
            failure,
            knock,
            elapsed_ms,
        };
        let failed = DirectFailed {
            endpoint: "85.126.226.2:21010".to_owned(),
            attempts: vec![
                attempt(DirectFailure::Refused, KnockState::Sent(62201), 300),
                attempt(DirectFailure::ConnectTimeout { ms: 5700 }, KnockState::Sent(62201), 6000),
            ],
        };
        let text = failed.user_message("360853086");
        assert!(text.starts_with(crate::client::FORCED_DIRECT_FAILED));
        assert_eq!(
            text,
            FD_TIMEOUT_KNOCKED.replacen("{}", "{360853086 (85.126.226.2:21010, 300 + 6000 ms)}", 1)
        );
        // The server report leads with the final reason and keeps the earlier one.
        let detail = failed.detail();
        assert!(detail.starts_with("connect timeout: no answer to the TCP connect within 5700 ms"), "{detail}");
        assert!(detail.contains("before: refused"), "{detail}");

        // The catch-all carries the error itself, braces made harmless.
        let failed = DirectFailed {
            endpoint: "h:1".to_owned(),
            attempts: vec![attempt(
                DirectFailure::ConnectError("weird {os} error".to_owned()),
                KnockState::Off,
                12,
            )],
        };
        let text = failed.user_message("1");
        assert_eq!(text, FD_ERROR.replacen("{}", "{1 (h:1, 12 ms; weird (os) error)}", 1));
        assert_eq!(text.matches('{').count(), 1);

        // Knocking on, but nothing went out: that is the reason, whatever the connect did.
        for failure in [DirectFailure::Refused, DirectFailure::ConnectTimeout { ms: 1 }] {
            let failed = DirectFailed {
                endpoint: "h:1".to_owned(),
                attempts: vec![attempt(failure, KnockState::NotSent("no key".to_owned()), 1)],
            };
            assert!(failed.user_message("1").contains("could not send the knock"));
        }

        // Every reason has its own text, and every text has exactly one placeholder.
        for key in FORCED_DIRECT_REASON_KEYS {
            assert!(key.starts_with("Direct connection to {} failed"), "{key}");
            assert_eq!(key.matches("{}").count(), 1, "{key}");
            assert_eq!(key.matches('{').count(), 1, "{key}");
        }
    }

    // Base64 of the real fwknop 2.6.11 datagram captured with
    //   fwknop -A tcp/21118 -a 203.0.113.9 -D 127.0.0.1 --use-hmac --test -B <file>
    // and the two keys it was built with. If our encoder ever stops reproducing this
    // byte for byte, fwknopd stops accepting our knocks, so this is the contract test.
    const REAL_PACKET: &str = "8pltmoCCjfxjdY6eh0zhV7aji3E8CBKpjeZiJ2aEQMtJcAdAIcE4mOo0FOp2sPRdl9piM+olVG6fx5cFx3JRhJK5ofSlNqyKW0c1Wsq5pYcUYgxVr/2+EN7zts9uiIzf8nIrem1vCiD6+NbWB4H2dnbhG3G9hx+gvX3ZHCM2TxNe0VJ5d7jsKY8UPBEXJdEeghe/3atDXDTm2IseXlVaPrEI7WEIBZ/3w";
    const REAL_KEY_B64: &str = "dGJmZGVzay1sYWItc3BhLWtleS0wMDAx";
    const REAL_HMAC_B64: &str = "dGJmZGVzay1sYWItc3BhLWhtYWMtMDAwMQ==";
    const REAL_PLAINTEXT: &str = "3744117591952352:bmVtbw:1791320830:3.0.0:1:MjAzLjAuMTEzLjksdGNwLzIxMTE4:E5d/auXbR7n6YGSIjFGv71+z1cVII6/OmCm7Oy7qam4";

    fn b64_decode(s: &str) -> Vec<u8> {
        let padded = format!("{}{}", s, "=".repeat((4 - s.len() % 4) % 4));
        crate::common::decode64(padded).expect("base64")
    }

    fn test_cfg() -> KnockConfig {
        KnockConfig {
            port: 62201,
            key: b64_decode(REAL_KEY_B64),
            hmac_key: b64_decode(REAL_HMAC_B64),
            delay: Duration::ZERO,
            user: "nemo".to_owned(),
            source_ip: "203.0.113.9".to_owned(),
        }
    }

    /// Reverse of `build_spa_packet`, test-only: proves we can read what fwknop wrote
    /// and that we wrote what fwknop would have read.
    fn decode_spa_packet(packet: &str, cfg: &KnockConfig) -> (bool, String) {
        use aes::cipher::BlockDecryptMut;
        type Aes256CbcDec = cbc::Decryptor<Aes256>;

        let (body, tag) = packet.split_at(packet.len() - 43);
        let encoded = format!("{}{}", SALTED_B64_PREFIX, body);
        let mut mac = HmacSha256::new_from_slice(&cfg.hmac_key).expect("hmac key");
        mac.update(encoded.as_bytes());
        let hmac_ok = mac.verify_slice(&b64_decode(tag)).is_ok();

        let raw = b64_decode(&encoded);
        assert_eq!(&raw[..8], b"Salted__");
        let (key, iv) = evp_bytes_to_key(&cfg.key, &raw[8..16]);
        let mut buf = raw[16..].to_vec();
        let plaintext = Aes256CbcDec::new(&key.into(), &iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .expect("decrypt");
        (hmac_ok, String::from_utf8(plaintext.to_vec()).expect("utf8"))
    }

    // Wire compatibility, direction 1: we understand fwknop's packet.
    #[test]
    fn spa_matches_a_real_fwknop_packet() {
        let (hmac_ok, plaintext) = decode_spa_packet(REAL_PACKET, &test_cfg());
        assert!(hmac_ok, "HMAC over the salted-prefixed base64 must verify");
        assert_eq!(plaintext, REAL_PLAINTEXT);
    }

    // Wire compatibility, direction 2: given fwknop's own nonce, timestamp and salt, our
    // encoder reproduces fwknop's datagram exactly. This is the strongest statement
    // available without running fwknopd: same bytes in, same bytes out.
    #[test]
    fn spa_encoder_reproduces_the_real_fwknop_packet() {
        let cfg = test_cfg();
        let raw = b64_decode(&format!(
            "{}{}",
            SALTED_B64_PREFIX,
            &REAL_PACKET[..REAL_PACKET.len() - 43]
        ));
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&raw[8..16]);
        let built = build_spa_packet(
            &cfg,
            "203.0.113.9,tcp/21118",
            1_791_320_830,
            "3744117591952352",
            &salt,
        )
        .expect("build");
        assert_eq!(built, REAL_PACKET);
    }

    // The nonce and salt are the only things that vary per packet, and both must reach
    // the digest/ciphertext, or fwknopd's replay cache would reject every repeat.
    #[test]
    fn spa_packets_differ_per_knock() {
        let cfg = test_cfg();
        let a = build_spa_packet(&cfg, "0.0.0.0,tcp/21118", 1_791_320_830, "1111111111111111", &[1u8; 8])
            .expect("a");
        let b = build_spa_packet(&cfg, "0.0.0.0,tcp/21118", 1_791_320_830, "2222222222222222", &[1u8; 8])
            .expect("b");
        let c = build_spa_packet(&cfg, "0.0.0.0,tcp/21118", 1_791_320_830, "1111111111111111", &[2u8; 8])
            .expect("c");
        assert_ne!(a, b, "a different nonce must change the packet");
        assert_ne!(a, c, "a different salt must change the packet");
        // ...and all three are still well-formed and readable by the daemon.
        for packet in [&a, &b, &c] {
            let (hmac_ok, plaintext) = decode_spa_packet(packet, &cfg);
            assert!(hmac_ok);
            assert!(plaintext.contains(":3.0.0:1:"));
        }
    }

    // The decisive check: a REAL fwknopd accepts what we send. The two tests above prove
    // our bytes match a captured packet; this one proves the daemon agrees, through the
    // production `knock()` path with a fresh nonce, timestamp and salt.
    //
    // Ignored because it needs a daemon running. To re-verify (no root needed — UDP
    // server mode binds a high port and -t skips the firewall commands):
    //
    //   cat > access.conf <<'EOF'
    //   SOURCE                  ANY
    //   KEY_BASE64              dGJmZGVzay1sYWItc3BhLWtleS0wMDAx
    //   HMAC_KEY_BASE64         dGJmZGVzay1sYWItc3BhLWhtYWMtMDAwMQ==
    //   REQUIRE_SOURCE_ADDRESS  N
    //   OPEN_PORTS              tcp/21118
    //   EOF
    //   chmod 600 access.conf; : > fwknopd.conf; chmod 600 fwknopd.conf
    //   fwknopd -c fwknopd.conf -a access.conf -r . -d ./digest.cache \
    //           -p ./fwknopd.pid -U -t -f -v
    //   cargo test --lib nemo_direct::tests::knock_is_accepted -- --ignored
    //
    // fwknopd must log "SPA Packet from IP: 127.0.0.1 received with access source match"
    // and then the tcp/21118 request. "Error creating fko context" means it rejected us.
    #[test]
    #[ignore = "needs a local fwknopd (see the comment above for the one-liner)"]
    fn knock_is_accepted_by_a_live_fwknopd() {
        let cfg = KnockConfig {
            port: 62201,
            source_ip: "0.0.0.0".to_owned(),
            ..test_cfg()
        };
        hbb_common::tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(async {
                knock("127.0.0.1", 21118, &cfg).await.expect("knock sent");
            });
    }

    #[test]
    fn rand16_is_always_sixteen_digits() {
        for _ in 0..64 {
            let r = random_rand16();
            assert_eq!(r.len(), 16, "{r}");
            assert!(r.chars().all(|c| c.is_ascii_digit()), "{r}");
        }
    }

    #[test]
    fn endpoints_parse_the_pushed_format() {
        let map = parse_endpoints(
            "123456789,203.0.113.5:21118;987654321,vpn.example.com:31118,62202;\
             555000111,[2001:db8::1]:21118",
        );
        assert_eq!(map.len(), 3);
        assert_eq!(
            map["123456789"],
            DirectEndpoint {
                host: "203.0.113.5".to_owned(),
                port: 21118,
                knock_port: None
            }
        );
        assert_eq!(
            map["987654321"],
            DirectEndpoint {
                host: "vpn.example.com".to_owned(),
                port: 31118,
                knock_port: Some(62202)
            }
        );
        // IPv6 keeps its brackets so target() stays a valid host:port string.
        assert_eq!(map["555000111"].host, "[2001:db8::1]");
        assert_eq!(map["555000111"].target(), "[2001:db8::1]:21118");
    }

    // One bad row must not cost the whole fleet its endpoints: the map arrives as a
    // single policy string, so lenient parsing is the difference between "one
    // workstation relays" and "every workstation relays".
    #[test]
    fn a_malformed_entry_does_not_discard_the_others() {
        let map = parse_endpoints(
            "good,203.0.113.5:21118;noport,203.0.113.6;badport,203.0.113.7:abc;\
             ,203.0.113.8:21118;zeroport,203.0.113.9:0;;  ;also-good,203.0.113.10:21119",
        );
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("good"));
        assert!(map.contains_key("also-good"));
    }

    #[test]
    fn an_empty_endpoint_map_yields_nothing() {
        assert!(parse_endpoints("").is_empty());
        assert!(parse_endpoints("   ").is_empty());
        assert!(parse_endpoints(";;;").is_empty());
    }

    #[test]
    fn knock_keys_parse_per_peer() {
        let map = parse_knock_keys(&format!(
            "123456789,{k},{h}; 987654321,{k},{h}",
            k = REAL_KEY_B64,
            h = REAL_HMAC_B64
        ));
        assert_eq!(map.len(), 2);
        let (key, hmac_key) = &map["123456789"];
        assert_eq!(key, &b64_decode(REAL_KEY_B64));
        assert_eq!(hmac_key, &b64_decode(REAL_HMAC_B64));
        assert!(map.contains_key("987654321"));
    }

    // Key isolation at the client layer: a controller handed only pc2's row holds no key
    // for pc7, so `knock_config_for("pc7")` could never build pc7's SPA from this map.
    // The server enforces the split by filtering the rows per controller; this proves the
    // client does not invent a key for a peer it was not given one for.
    #[test]
    fn a_peer_absent_from_the_knock_key_map_has_no_key() {
        let map = parse_knock_keys(&format!("pc2,{k},{h}", k = REAL_KEY_B64, h = REAL_HMAC_B64));
        assert!(map.contains_key("pc2"));
        assert!(!map.contains_key("pc7"));
    }

    // One bad row must not cost the fleet its per-peer keys: the map is a single policy
    // string, so a typo in one workstation's row is skipped, not fatal.
    #[test]
    fn a_malformed_knock_key_row_does_not_discard_the_others() {
        let map = parse_knock_keys(&format!(
            "good,{k},{h};\
             missinghmac,{k};\
             badb64,not@@base64,{h};\
             ,{k},{h};\
             empty,,;\
             ;  ;\
             also-good,{k},{h}",
            k = REAL_KEY_B64,
            h = REAL_HMAC_B64
        ));
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("good"));
        assert!(map.contains_key("also-good"));
    }

    #[test]
    fn an_empty_knock_key_map_yields_nothing() {
        assert!(parse_knock_keys("").is_empty());
        assert!(parse_knock_keys("   ").is_empty());
        assert!(parse_knock_keys(";;;").is_empty());
    }
}
