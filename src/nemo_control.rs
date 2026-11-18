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
/// "Y" = a valid ticket for a SIGNED-IN user that names this machine stands in for the
/// local password: the session is admitted without one. The password keeps working for
/// everyone else. Only the password factor is replaced -- approve-mode "click" still asks
/// the local user, and 2FA is still asked.
pub const OPTION_LDAP_LOGIN_SUFFICIENT: &str = "nemo-ldap-login-sufficient";
/// "Y" = this machine accepts none of its own passwords (one-time, permanent, preset,
/// logon-screen, recent-session reconnect). What still admits a session: the ticket of a
/// signed-in user who may control this machine (the password is gone, so this toggle on
/// its own already makes the sign-in the credential), or -- where the approve mode offers
/// the Accept button at all -- the person at the machine. Everything else is refused with
/// LOGIN_MSG_LOCAL_PASSWORD_DISABLED.
pub const OPTION_DISABLE_LOCAL_PASSWORD: &str = "nemo-disable-local-password";

/// What a controller is told when this machine refuses it under "disable local password".
/// A plain sentence: the controller translates it (lang/de.rs) and shows it as the login
/// error, which also ends the attempt on controllers that predate the policy.
pub const LOGIN_MSG_LOCAL_PASSWORD_DISABLED: &str = "Password login is disabled by policy on this computer. Sign in to TBFDesk with an account that may control it, and connect again.";

/// Policy keys this module owns. They are always applied LOCKED, whatever the policy's
/// allow_user_override says: a user must not be able to switch enforcement off on the
/// machine they are about to be refused by, or hand themselves another ticket.
pub const NEMO_CONTROL_SETTINGS: &[&str] = &[
    OPTION_CONTROL_TICKET,
    OPTION_CONTROL_EPOCH,
    OPTION_REQUIRE_CONTROL_TICKET,
    OPTION_LOCK_AFTER_SESSION_END,
    OPTION_LDAP_LOGIN_SUFFICIENT,
    OPTION_DISABLE_LOCAL_PASSWORD,
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

pub fn ldap_login_sufficient() -> bool {
    Config::get_option(OPTION_LDAP_LOGIN_SUFFICIENT) == "Y"
}

pub fn local_password_disabled() -> bool {
    Config::get_option(OPTION_DISABLE_LOCAL_PASSWORD) == "Y"
}

/// How a login on this target is decided before any password is looked at.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoginRoute {
    /// Admitted on the ticket alone: no password (2FA and the blocklist still apply).
    Admit,
    /// Put to the local user (Accept), as approve-mode "click" does. No password is
    /// looked at, so a typed one is neither accepted nor counted as a failure.
    AskLocalUser,
    /// Refused: the local password is disabled and nothing else can admit this login.
    Refuse,
    /// The normal path, exactly as without these policies: approve mode, recent
    /// session, password.
    Normal,
}

/// The decision, kept pure so the whole matrix is unit-tested.
/// - `ticket_user`: the user named by a VALID ticket presented on THIS login (None = no
///   valid ticket; "" = a ticket without a signed-in user, which proves no person).
/// - `click_only`: approve mode "click" (and not the logon-screen password exception):
///   the local user must accept every session, a ticket included.
/// - `_click_offered`: whether the approve mode shows an Accept button. No longer part of
///   the decision (operator decision 2026-11-18): with the local password disabled, a
///   login without a signed-in ticket is REFUSED in every approve mode -- nobody who only
///   knows the ID can raise an Accept popup on such a machine.
///
/// Both policies off -> always `Normal`: these switches can only change a machine that
/// opted in, never weaken one that did not.
pub fn login_route(
    ticket_user: Option<&str>,
    ldap_sufficient: bool,
    local_password_disabled: bool,
    click_only: bool,
    _click_offered: bool,
) -> LoginRoute {
    let signed_in = ticket_user.map(|u| !u.trim().is_empty()).unwrap_or(false);
    if local_password_disabled {
        // The machine's own passwords are off: only a signed-in user may get in at all,
        // and approve mode "click" still asks the local user for that user's session.
        if !signed_in {
            LoginRoute::Refuse
        } else if click_only {
            LoginRoute::AskLocalUser
        } else {
            LoginRoute::Admit
        }
    } else if signed_in && ldap_sufficient && !click_only {
        LoginRoute::Admit
    } else {
        LoginRoute::Normal
    }
}

/// What the target tells a switch-sides connect-back that asks for anything but a
/// remote-desktop session. A real controller never does (it connects back with plain
/// `--connect`), so this is not translated.
pub const LOGIN_MSG_SWITCH_SIDES_DESKTOP_ONLY: &str =
    "Switch sides only opens a remote desktop session.";

/// How the target decides a switch-sides connect-back (Flutter desktop only).
///
/// This machine handed the other side a one-time uuid. The other side now connects back
/// with it (`SwitchSidesResponse` in server/connection.rs). The uuid comes from one of two
/// flows:
/// - **Switch sides:** the person at THIS machine clicked "Switch Sides" in a session
///   they were controlling. The uuid is their consent.
/// - **Switch back:** this machine's own client asked for the uuid automatically
///   (model.dart `switch_back` -> sessionSwitchSides). It was answering the peer, which
///   pressed "Switch Sides" in its connection-manager window. The peer is the
///   controller this machine admitted, with password or ticket (and 2FA where required),
///   in the session that started the first switch. Nobody here clicks anything. The uuid
///   is bound to that earlier admission, like a recent-session reconnect.
///
/// Either way the uuid stands where the password or the Accept click would stand, and
/// for nothing else. What decides a normal login still decides this one:
/// - the management authorization (`apply_management_authorization`): the ticket,
///   "require management authorization", a ticket that does not list this machine;
/// - the blocklist (`send_logon_response_and_keep_alive`);
/// - "disable local password", through the same `login_route` as a login.
///
/// The caller runs the ticket check first and passes the resulting route. 2FA is not
/// asked, as in stock RustDesk: the switch was the local user's own decision, or (switch
/// back) the return of a controller already admitted.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SwitchSides {
    /// Admitted on the uuid, as before these checks existed.
    Admit,
    /// Refused: the connect-back asked for file transfer, a camera, a terminal or a
    /// tunnel, in its own `lr` or in an earlier LoginRequest on the same connection.
    /// Only the login arm checks those permissions, and a switch never needs one.
    RefuseKind,
    /// Refused: the local password is disabled, and the connect-back carries no ticket
    /// of a signed-in user (`LoginRoute::Refuse`, LOGIN_MSG_LOCAL_PASSWORD_DISABLED).
    RefuseLocalPasswordDisabled,
}

/// The decision, kept pure so it is unit-tested against `login_route`.
/// - `plain_desktop`: nothing on this connection names another session kind: the
///   connect-back's `lr.union` is empty, and no earlier LoginRequest on the connection
///   set file transfer, camera, terminal or a tunnel (the login arm sets those before
///   the password is checked). A real controller's connect-back is always plain: it
///   sends no LoginRequest before its SwitchSidesResponse.
/// - `route`: `login_route` for the ticket this connect-back presented.
///
/// Admit, AskLocalUser and Normal all admit: the uuid replaces the password and the
/// Accept step (see above for what it stands for). Only Refuse refuses. A login with the
/// same ticket is refused there too, so the uuid opens nothing a login could not.
pub fn switch_sides_decision(plain_desktop: bool, route: LoginRoute) -> SwitchSides {
    if !plain_desktop {
        SwitchSides::RefuseKind
    } else if route == LoginRoute::Refuse {
        SwitchSides::RefuseLocalPasswordDisabled
    } else {
        SwitchSides::Admit
    }
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

    /// The approve modes as the target computes the two flags (connection.rs):
    /// (click_only, click_offered).
    const MODE_PASSWORD: (bool, bool) = (false, false);
    const MODE_BOTH: (bool, bool) = (false, true);
    const MODE_CLICK: (bool, bool) = (true, true);

    #[test]
    fn login_route_matrix() {
        use LoginRoute::*;
        let alice = Some("alice");
        // (ticket user, ldap sufficient, local pw disabled, approve mode) -> route
        let cases: &[(Option<&str>, bool, bool, (bool, bool), LoginRoute)] = &[
            // LDAP sufficient: a signed-in user's valid ticket replaces the password...
            (alice, true, false, MODE_BOTH, Admit),
            (alice, true, false, MODE_PASSWORD, Admit),
            // ...but not the local user's consent when the approve mode is click.
            (alice, true, false, MODE_CLICK, Normal),
            // ...and everybody else keeps the password (or click) as before.
            (None, true, false, MODE_BOTH, Normal),
            (None, true, false, MODE_PASSWORD, Normal),
            // A ticket WITHOUT a signed-in user (sign-in optional) proves no person.
            (Some(""), true, false, MODE_BOTH, Normal),
            (Some("  "), true, false, MODE_PASSWORD, Normal),
            // Local password disabled: the sign-in is the credential, with or without
            // the "LDAP sufficient" switch...
            (alice, false, true, MODE_BOTH, Admit),
            (alice, true, true, MODE_PASSWORD, Admit),
            (alice, false, true, MODE_PASSWORD, Admit),
            // ...click still means the local user accepts every session...
            (alice, true, true, MODE_CLICK, AskLocalUser),
            (alice, false, true, MODE_CLICK, AskLocalUser),
            // ...and a session that is not signed in is refused in EVERY approve mode
            // (operator decision 2026-11-18: no Accept popup for strangers)...
            (None, false, true, MODE_BOTH, Refuse),
            (None, true, true, MODE_CLICK, Refuse),
            (None, false, true, MODE_CLICK, Refuse),
            (Some(""), false, true, MODE_BOTH, Refuse),
            (Some(""), false, true, MODE_CLICK, Refuse),
            (None, false, true, MODE_PASSWORD, Refuse),
            (None, true, true, MODE_PASSWORD, Refuse),
            (Some(""), true, true, MODE_PASSWORD, Refuse),
            (Some("  "), false, true, MODE_PASSWORD, Refuse),
        ];
        for (user, ldap, nopw, (click_only, click_offered), want) in cases {
            assert_eq!(
                login_route(*user, *ldap, *nopw, *click_only, *click_offered),
                *want,
                "user={user:?} ldap={ldap} nopw={nopw} click_only={click_only} click_offered={click_offered}"
            );
        }
    }

    #[test]
    fn both_policies_off_never_change_how_a_login_is_decided() {
        // The never-weakens proof: with neither switch set, every input -- any ticket,
        // any approve mode -- takes the normal path, i.e. today's code unchanged.
        let users = [None, Some(""), Some("  "), Some("alice"), Some("admin")];
        for user in users {
            for click_only in [false, true] {
                for click_offered in [false, true] {
                    assert_eq!(
                        login_route(user, false, false, click_only, click_offered),
                        LoginRoute::Normal,
                        "user={user:?} click_only={click_only} click_offered={click_offered}"
                    );
                }
            }
        }
    }

    #[test]
    fn only_a_signed_in_ticket_admits_without_a_password() {
        // Whatever the switches, Admit needs a named user: no ticket, or a ticket of a
        // controller nobody signed in on, never skips the password / the local user.
        for ldap in [false, true] {
            for nopw in [false, true] {
                for (click_only, click_offered) in [MODE_PASSWORD, MODE_BOTH, MODE_CLICK] {
                    for user in [None, Some(""), Some(" \t ")] {
                        assert_ne!(
                            login_route(user, ldap, nopw, click_only, click_offered),
                            LoginRoute::Admit,
                            "user={user:?} ldap={ldap} nopw={nopw}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_disabled_local_password_never_takes_the_password_path() {
        // With the local password disabled the normal (password) path is never chosen:
        // the login is admitted on the ticket, put to the local user, or refused.
        for ldap in [false, true] {
            for (click_only, click_offered) in [MODE_PASSWORD, MODE_BOTH, MODE_CLICK] {
                for user in [None, Some(""), Some("alice")] {
                    assert_ne!(
                        login_route(user, ldap, true, click_only, click_offered),
                        LoginRoute::Normal,
                        "user={user:?} ldap={ldap}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_disabled_local_password_refuses_everyone_not_signed_in() {
        // Operator decision 2026-11-18: whatever the approve mode, a login without a
        // signed-in ticket never reaches the password, the local user or a session.
        for ldap in [false, true] {
            for (click_only, click_offered) in [MODE_PASSWORD, MODE_BOTH, MODE_CLICK] {
                for user in [None, Some(""), Some("  ")] {
                    assert_eq!(
                        login_route(user, ldap, true, click_only, click_offered),
                        LoginRoute::Refuse,
                        "user={user:?} ldap={ldap} click_only={click_only}"
                    );
                }
            }
        }
    }

    /// Every input `login_route` takes, with `click_only` forced the way the switch-sides
    /// arm passes it (true). `click_offered` is no longer part of the decision; it is
    /// still varied.
    fn every_switch_route() -> Vec<(Option<&'static str>, bool, bool, bool, LoginRoute)> {
        let mut v = Vec::new();
        for user in [None, Some(""), Some("  "), Some("alice"), Some("admin")] {
            for ldap in [false, true] {
                for nopw in [false, true] {
                    for click_offered in [false, true] {
                        v.push((
                            user,
                            ldap,
                            nopw,
                            click_offered,
                            login_route(user, ldap, nopw, true, click_offered),
                        ));
                    }
                }
            }
        }
        v
    }

    #[test]
    fn a_switch_is_admitted_as_before_when_neither_policy_is_set() {
        // The never-weakens proof for switch sides: with neither machine policy, a plain
        // connect-back is admitted on its uuid whatever ticket it carries. That is the
        // old behaviour; the ticket check runs before and refuses on its own terms only
        // where tickets are required or the ticket denies this machine.
        // "LDAP login is sufficient" alone never refuses a switch either.
        for (user, ldap, nopw, click_offered, route) in every_switch_route() {
            if nopw {
                continue;
            }
            assert_eq!(
                switch_sides_decision(true, route),
                SwitchSides::Admit,
                "user={user:?} ldap={ldap} click_offered={click_offered}"
            );
        }
    }

    #[test]
    fn a_disabled_local_password_refuses_a_switch_without_a_signed_in_ticket() {
        for (user, ldap, nopw, click_offered, route) in every_switch_route() {
            if !nopw {
                continue;
            }
            let signed_in = user.map(|u| !u.trim().is_empty()).unwrap_or(false);
            let want = if signed_in {
                // A signed-in user's ticket admits; the uuid stands where click mode's
                // Accept would.
                SwitchSides::Admit
            } else {
                SwitchSides::RefuseLocalPasswordDisabled
            };
            assert_eq!(
                switch_sides_decision(true, route),
                want,
                "user={user:?} ldap={ldap} click_offered={click_offered}"
            );
        }
    }

    #[test]
    fn a_switch_is_refused_exactly_where_a_login_is_refused() {
        // Same as a login: the switch refuses iff login_route refuses, for every input
        // and every approve mode a login could see (click_only false or true).
        for user in [None, Some(""), Some("alice")] {
            for ldap in [false, true] {
                for nopw in [false, true] {
                    for (click_only, click_offered) in [MODE_PASSWORD, MODE_BOTH, MODE_CLICK] {
                        let login = login_route(user, ldap, nopw, click_only, click_offered);
                        let switch = switch_sides_decision(
                            true,
                            login_route(user, ldap, nopw, true, click_offered),
                        );
                        assert_eq!(
                            login == LoginRoute::Refuse,
                            switch != SwitchSides::Admit,
                            "user={user:?} ldap={ldap} nopw={nopw} click_only={click_only}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_switch_never_opens_anything_but_a_desktop_session() {
        // File transfer, camera, terminal or tunnel in a connect-back are refused for every
        // route, an admitting ticket included: their permissions are only checked in the
        // LoginRequest arm.
        for route in [
            LoginRoute::Admit,
            LoginRoute::AskLocalUser,
            LoginRoute::Normal,
            LoginRoute::Refuse,
        ] {
            assert_eq!(
                switch_sides_decision(false, route),
                SwitchSides::RefuseKind,
                "{route:?}"
            );
        }
    }

    #[test]
    fn the_machine_policy_keys_are_locked_policy_settings() {
        // Applied LOCKED whatever allow_user_override says, and never stored as a plain
        // setting (nemo_management_client keys both off this list).
        assert!(NEMO_CONTROL_SETTINGS.contains(&OPTION_LDAP_LOGIN_SUFFICIENT));
        assert!(NEMO_CONTROL_SETTINGS.contains(&OPTION_DISABLE_LOCAL_PASSWORD));
    }

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
