//! Management authorization for every session, direct ones included ("control tickets").
//!
//! Who may control which machine, and with which features (clipboard, file transfer,
//! keyboard, ...), is decided in the admin dashboard: per LDAP user, per device policy,
//! globally. Until now the server could only enforce that while it was ON the
//! connection path -- at the rendezvous, where it attached ControlPermissions to the
//! punch. A direct session (published endpoint, or a LAN IP) never touches the
//! rendezvous, so it arrived with no permissions and no user gate at all: the target
//! fell back to its own local settings, and a user the operator had denied clipboard,
//! or denied this machine entirely, could get both by connecting directly.
//!
//! The fix puts the decision where every session passes: the TARGET.
//!
//! 1. The server hands each signed-in controller a **ticket** with its policy poll: its
//!    peer id and device public key, the LDAP user, the effective permission bits, the
//!    machines it may control, an issue time, an expiry and the server's current
//!    authorization **epoch** -- all signed with the management key.
//! 2. The controller sends the ticket in its LoginRequest, plus its device key's
//!    signature over this connection's challenge (the target's random `Hash.challenge`),
//!    so a copied ticket is useless to anyone without that device key.
//! 3. The target verifies all of it against its pinned management public key, applies
//!    the permissions exactly as if the server had attached them at the rendezvous, and
//!    -- when the operator turns on "require management authorization" -- refuses any
//!    session that does not carry a valid ticket.
//!
//! Revocation: the server pushes its epoch to every machine, and moves it whenever
//! anything that decides authorization changes (permissions, policies, user
//! assignments, block/allow). A target refuses a ticket older than the epoch it knows,
//! so a change takes effect within one target poll even though tickets are only
//! re-issued when something changes.

use hbb_common::{
    config::{Config, LocalConfig},
    log,
    sodiumoxide::crypto::sign,
};
use serde_derive::{Deserialize, Serialize};

/// The controller's current ticket (pushed in its policy poll).
pub const OPTION_CONTROL_TICKET: &str = "nemo-control-ticket";
/// The server's authorization epoch (pushed to every machine).
pub const OPTION_CONTROL_EPOCH: &str = "nemo-control-epoch";
/// "Y" = refuse every session without a valid ticket (set in the dashboard).
pub const OPTION_REQUIRE_CONTROL_TICKET: &str = "nemo-require-control-ticket";
/// "Y" = lock this machine's desktop when a remote-control session to it ends, whatever
/// the controller's own "Lock after session end" toggle says. The target enforces it, so
/// a controller cannot opt out.
pub const OPTION_LOCK_AFTER_SESSION_END: &str = "nemo-lock-after-session-end";

/// Policy keys this module owns. They are always applied LOCKED, whatever the policy's
/// allow_user_override says: a user must not be able to switch enforcement off on the
/// machine they are about to be refused by, or hand themselves another ticket.
pub const NEMO_CONTROL_SETTINGS: &[&str] = &[
    OPTION_CONTROL_TICKET,
    OPTION_CONTROL_EPOCH,
    OPTION_REQUIRE_CONTROL_TICKET,
    OPTION_LOCK_AFTER_SESSION_END,
];

/// Tolerated clock difference between server and target, both ways.
const CLOCK_SKEW_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ticket {
    pub v: u32,
    /// The controller's peer id.
    pub ctl: String,
    /// The controller's device public key (base64 Ed25519).
    pub dk: String,
    /// The signed-in LDAP user ("" when the server does not require sign-in).
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub admin: bool,
    /// Peer ids this controller may control; `["*"]` = every machine.
    pub targets: Vec<String>,
    /// ControlPermissions bits: two per feature at `index * 2`, 1 = off, 2 = on,
    /// 0 = not decided (the target's own setting applies).
    #[serde(default)]
    pub perm: u64,
    pub iat: u64,
    pub exp: u64,
    pub epoch: u64,
}

/// Why a presented ticket was not accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// The ticket is valid and says this controller may NOT control this machine. Always
    /// refused: the server has decided, and only a cooperative client sends a ticket.
    Denied(String),
    /// Not usable (signature, expiry, wrong owner, outdated). Refused only where
    /// authorization is required; elsewhere it grants nothing and is ignored.
    Invalid(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Denied(r) | Refusal::Invalid(r) => f.write_str(r),
        }
    }
}

/// What a valid ticket grants on this target.
#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    pub user: String,
    pub admin: bool,
    pub permissions: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The bytes the controller signs with its device key: bound to the target and to this
/// connection's random challenge, so neither a recorded login nor a copied ticket can be
/// replayed against this or any other machine.
pub fn challenge_message(target_id: &str, challenge: &str) -> Vec<u8> {
    format!("nemo-ctl:{target_id}:{challenge}").into_bytes()
}

/// `payload_b64.sig_b64` -> the ticket, if the management key signed it and it is
/// within its validity window.
pub fn parse_and_verify(raw: &str, mgmt_pk: &sign::PublicKey, now: u64) -> Result<Ticket, String> {
    let (payload_b64, sig_b64) = raw.trim().split_once('.').ok_or("malformed ticket")?;
    let payload = crate::common::decode64(payload_b64).map_err(|_| "malformed ticket")?;
    let sig_bytes = crate::common::decode64(sig_b64).map_err(|_| "malformed ticket")?;
    let sig = sign::Signature::from_bytes(&sig_bytes).map_err(|_| "malformed ticket")?;
    if !sign::verify_detached(&sig, &payload, mgmt_pk) {
        return Err("the ticket was not issued by this management server".to_owned());
    }
    let t: Ticket = serde_json::from_slice(&payload).map_err(|_| "malformed ticket")?;
    if t.v != 1 {
        return Err(format!("unsupported ticket version {}", t.v));
    }
    if now > t.exp.saturating_add(CLOCK_SKEW_SECS) {
        return Err("the authorization has expired; the connecting computer must poll the server again".to_owned());
    }
    if t.iat > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err("the authorization is dated in the future (check the clocks)".to_owned());
    }
    Ok(t)
}

/// Controller side: what to put into the LoginRequest for `target_id`. `None` when this
/// machine holds no ticket or no device key -- the target then decides (refuse when it
/// requires authorization, its own settings otherwise).
/// The signed-in user's ticket, in the per-OS-user LocalConfig, written by the poller
/// that polled WITH that user's token. On Windows two processes poll: the SYSTEM
/// `--server` (no user token, so under required sign-in no ticket) and the user's own
/// UI process (the user's ticket). A session process gets its Config synced from the
/// SYSTEM one, so the Config copy never carries the user's ticket there; LocalConfig is
/// per OS user and never synced from the service. On Linux both are one process.
pub const LOCAL_USER_TICKET: &str = "nemo-user-control-ticket";

/// Called after every accepted poll with that poll's ticket ("" = none), and with ""
/// when the sign-in is dropped.
pub fn remember_user_ticket(ticket: &str) {
    if LocalConfig::get_option(LOCAL_USER_TICKET) != ticket {
        LocalConfig::set_option(LOCAL_USER_TICKET.to_owned(), ticket.to_owned());
    }
}

fn presented_ticket() -> String {
    let user = LocalConfig::get_option(LOCAL_USER_TICKET);
    if !user.trim().is_empty() {
        return user;
    }
    Config::get_option(OPTION_CONTROL_TICKET)
}

pub fn login_proof(target_id: &str, challenge: &str) -> Option<(String, Vec<u8>)> {
    let ticket = presented_ticket();
    if ticket.trim().is_empty() {
        return None;
    }
    let (_pk, sk) = crate::common::nemo_device_ed25519()?;
    let sig = sign::sign_detached(&challenge_message(target_id, challenge), &sk);
    Some((ticket.trim().to_owned(), sig.as_ref().to_vec()))
}

/// Target side, pure: decide on a presented ticket. `Ok(None)` = none presented,
/// `Err(reason)` = presented but not valid for this connection.
#[allow(clippy::too_many_arguments)]
pub fn check(
    ticket: &str,
    sig: &[u8],
    controller_id: &str,
    my_id: &str,
    challenge: &str,
    mgmt_pk: &sign::PublicKey,
    known_epoch: u64,
    now: u64,
) -> Result<Option<Grant>, Refusal> {
    if ticket.trim().is_empty() {
        return Ok(None);
    }
    let invalid = |r: &str| Refusal::Invalid(r.to_owned());
    let t = parse_and_verify(ticket, mgmt_pk, now).map_err(Refusal::Invalid)?;
    if t.ctl != controller_id {
        return Err(invalid("the authorization was issued to another computer"));
    }
    if t.epoch < known_epoch {
        return Err(invalid("the authorization is out of date (permissions changed); try again in a moment"));
    }
    let dk = crate::common::decode64(&t.dk)
        .ok()
        .and_then(|b| sign::PublicKey::from_slice(&b))
        .ok_or_else(|| invalid("malformed ticket key"))?;
    let sig = sign::Signature::from_bytes(sig)
        .map_err(|_| invalid("the connecting computer did not prove the authorization is its own"))?;
    if !sign::verify_detached(&sig, &challenge_message(my_id, challenge), &dk) {
        return Err(invalid("the connecting computer did not prove the authorization is its own"));
    }
    if !t.targets.iter().any(|x| x == "*" || x == my_id) {
        // The controller shows this text translated; `{name}` is the translator's
        // placeholder syntax (lang.rs), so the user name survives translation.
        return Err(Refusal::Denied(if t.user.is_empty() {
            "the connecting computer is not permitted to control this computer".to_owned()
        } else {
            format!("user {{{}}} is not permitted to control this computer", t.user)
        }));
    }
    Ok(Some(Grant {
        user: t.user,
        admin: t.admin,
        permissions: t.perm,
    }))
}

/// Target side, with this machine's configuration.
pub fn authorize(ticket: &str, sig: &[u8], controller_id: &str, challenge: &str) -> Result<Option<Grant>, Refusal> {
    if ticket.trim().is_empty() {
        return Ok(None);
    }
    let pk_b64 = Config::get_option("nemo-management-public-key");
    let Some(mgmt_pk) = crate::common::get_rs_pk(pk_b64.trim()) else {
        return Err(Refusal::Invalid("this computer has no management key to check the authorization with".to_owned()));
    };
    let epoch = Config::get_option(OPTION_CONTROL_EPOCH).trim().parse::<u64>().unwrap_or(0);
    check(ticket, sig, controller_id, &Config::get_id(), challenge, &mgmt_pk, epoch, now())
}

/// Does this machine refuse sessions without a valid ticket?
pub fn required() -> bool {
    Config::get_option(OPTION_REQUIRE_CONTROL_TICKET) == "Y"
}

pub fn lock_after_session_end() -> bool {
    Config::get_option(OPTION_LOCK_AFTER_SESSION_END) == "Y"
}

/// Combine two permission sets, the stricter one winning per feature: "off" from either
/// side is off; otherwise "on" from either side is on; otherwise not decided.
pub fn merge_strict(a: u64, b: u64) -> u64 {
    let mut out = 0u64;
    for i in 0..32 {
        let (x, y) = ((a >> (i * 2)) & 3, (b >> (i * 2)) & 3);
        let v = if x == 1 || y == 1 {
            1
        } else if x == 2 || y == 2 {
            2
        } else {
            0
        };
        out |= v << (i * 2);
    }
    out
}

pub fn log_grant(controller_id: &str, grant: &Option<Grant>) {
    match grant {
        Some(g) => log::info!(
            "session authorization: {} as user '{}'{} with permissions {:#x}",
            controller_id,
            g.user,
            if g.admin { " (admin)" } else { "" },
            g.permissions
        ),
        None => log::info!("session authorization: {} presented no ticket", controller_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(t: &Ticket, sk: &sign::SecretKey) -> String {
        let payload = serde_json::to_vec(t).unwrap();
        let sig = sign::sign_detached(&payload, sk);
        format!(
            "{}.{}",
            crate::common::encode64(&payload),
            crate::common::encode64(sig.as_ref())
        )
    }

    struct Fixture {
        mgmt: (sign::PublicKey, sign::SecretKey),
        dev: (sign::PublicKey, sign::SecretKey),
        ticket: Ticket,
    }

    fn fixture() -> Fixture {
        hbb_common::sodiumoxide::init().ok();
        let mgmt = sign::gen_keypair();
        let dev = sign::gen_keypair();
        let ticket = Ticket {
            v: 1,
            ctl: "480170882".into(),
            dk: crate::common::encode64(dev.0.as_ref()),
            user: "userA".into(),
            admin: false,
            targets: vec!["352069946".into()],
            perm: 1 << 4, // clipboard (index 2) off
            iat: 1_000,
            exp: 9_000,
            epoch: 500,
        };
        Fixture { mgmt, dev, ticket }
    }

    fn present(f: &Fixture, ticket: &str, target: &str, challenge: &str) -> Vec<u8> {
        let _ = ticket;
        sign::sign_detached(&challenge_message(target, challenge), &f.dev.1).as_ref().to_vec()
    }

    #[test]
    fn a_valid_ticket_grants_exactly_its_permissions() {
        let f = fixture();
        let raw = issue(&f.ticket, &f.mgmt.1);
        let sig = present(&f, &raw, "352069946", "c1");
        let g = check(&raw, &sig, "480170882", "352069946", "c1", &f.mgmt.0, 500, 2_000)
            .unwrap()
            .unwrap();
        assert_eq!(g.user, "userA");
        assert_eq!(g.permissions, 1 << 4);
    }

    #[test]
    fn every_way_to_misuse_a_ticket_is_refused() {
        let f = fixture();
        let raw = issue(&f.ticket, &f.mgmt.1);
        let sig = present(&f, &raw, "352069946", "c1");
        let ok = |raw: &str, sig: &[u8], ctl: &str, me: &str, ch: &str, epoch: u64, now: u64| {
            check(raw, sig, ctl, me, ch, &f.mgmt.0, epoch, now)
        };
        // Signed by another server.
        let rogue = sign::gen_keypair();
        assert!(ok(&issue(&f.ticket, &rogue.1), &sig, "480170882", "352069946", "c1", 500, 2_000).is_err());
        // Presented by another computer id.
        assert!(ok(&raw, &sig, "999999999", "352069946", "c1", 500, 2_000).is_err());
        // Replayed on another connection (different challenge) or another target.
        assert!(ok(&raw, &sig, "480170882", "352069946", "c2", 500, 2_000).is_err());
        let sig_other = present(&f, &raw, "111111111", "c1");
        assert!(
            matches!(ok(&raw, &sig_other, "480170882", "111111111", "c1", 500, 2_000), Err(Refusal::Denied(_))),
            "a machine not in the list is a decision, refused even where not enforced"
        );
        // Copied ticket, but no device key: signed by someone else's key.
        let thief = sign::gen_keypair();
        let thief_sig = sign::sign_detached(&challenge_message("352069946", "c1"), &thief.1);
        assert!(ok(&raw, thief_sig.as_ref(), "480170882", "352069946", "c1", 500, 2_000).is_err());
        // Revoked by a newer epoch; expired; from the future.
        assert!(ok(&raw, &sig, "480170882", "352069946", "c1", 501, 2_000).is_err());
        assert!(ok(&raw, &sig, "480170882", "352069946", "c1", 500, 9_000 + CLOCK_SKEW_SECS + 1).is_err());
        let mut future = f.ticket.clone();
        future.iat = 2_000 + CLOCK_SKEW_SECS + 10;
        assert!(ok(&issue(&future, &f.mgmt.1), &sig, "480170882", "352069946", "c1", 500, 2_000).is_err());
        // Tampered payload.
        let (p, s) = raw.split_once('.').unwrap();
        let mut payload = crate::common::decode64(p).unwrap();
        let last = payload.len() - 3;
        payload[last] ^= 1;
        let tampered = format!("{}.{}", crate::common::encode64(&payload), s);
        assert!(ok(&tampered, &sig, "480170882", "352069946", "c1", 500, 2_000).is_err());
        // No ticket at all is not an error: the caller decides.
        assert_eq!(ok("", &[], "480170882", "352069946", "c1", 500, 2_000), Ok(None));
    }

    #[test]
    fn a_wildcard_ticket_reaches_every_machine() {
        let mut f = fixture();
        f.ticket.targets = vec!["*".into()];
        f.ticket.admin = true;
        let raw = issue(&f.ticket, &f.mgmt.1);
        let sig = present(&f, &raw, "123", "c9");
        assert!(check(&raw, &sig, "480170882", "123", "c9", &f.mgmt.0, 0, 2_000).unwrap().is_some());
    }

    #[test]
    fn the_stricter_permission_wins() {
        // clipboard (2): on vs off -> off; file (3): on vs unset -> on; audio (4): unset both -> unset
        let a = (2 << 4) | (2 << 6);
        let b = 1 << 4;
        let m = merge_strict(a, b);
        assert_eq!((m >> 4) & 3, 1);
        assert_eq!((m >> 6) & 3, 2);
        assert_eq!((m >> 8) & 3, 0);
    }
}
