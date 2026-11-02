//! First-run provisioning in one string: `tbfdesk-setup-v1:<base64 json>`.
//!
//! A fresh client cannot reach this fork's server until SIX exact values have been typed
//! into it — the ID/rendezvous server, the relay, the api-server URL, the management
//! server URL, the server's identity key and, with a self-signed API, its certificate
//! fingerprint — and then the device key on top, because Layer 1 makes that mandatory.
//! Every one is long, most are base64, and a single wrong character fails as "cannot
//! reach the server", which looks exactly like a network problem. That was the first-run
//! experience on every machine.
//!
//! The server knows all of them, so the dashboard hands them over as one string (and the
//! same string is produced with a freshly generated device key inside it). This module is
//! the client half: parse it, check it, apply it.
//!
//! **It is the trust anchor, not merely a convenience.** The identity key inside is what
//! this client will verify the server with from then on, so a bundle from the wrong hands
//! points the machine at the wrong server — the same property the `host=..,key=..` exe
//! name has always had. Nothing here can fix that; it is why the dashboard says to move
//! it like a password. What this module can do, and does, is refuse a bundle that is
//! malformed, truncated or from a newer server rather than applying half of it.

use crate::common::decode64;
use hbb_common::{bail, config::Config, log, ResultType};
use serde_derive::{Deserialize, Serialize};

/// Versioned on purpose: a client that meets a v2 bundle must say so, not silently
/// ignore the fields it does not know.
pub const SETUP_PREFIX: &str = "tbfdesk-setup-v1:";

/// Every config key `apply_setup` may write. The UI import handler reads these back
/// after applying and re-sends them to the service over IPC — `apply_setup` writes
/// through `Config::set_option` (correct for the `--import-setup` CLI, which runs
/// before any service/IPC exists), but a GUI import must also reach the running
/// service or the live client keeps the old server until the next restart.
pub const APPLIED_OPTION_KEYS: &[&str] = &[
    "custom-rendezvous-server",
    "api-server",
    "nemo-management-server",
    "key",
    "nemo-management-public-key",
    "relay-server",
    "nemo-api-cert-fingerprint",
    "nemo-device-key",
    OPTION_MANAGEMENT_ENABLED,
];

/// The switch that makes the client actually POLL the management server it was just
/// given. Without it a setup string configures everything and the client then talks to
/// nobody: no policy, no login gate, no address-book version, no direct endpoints, no
/// audit — while looking perfectly configured. The dashboard shows such a machine as
/// online with a good device key and no poll, which is how this surfaced (OPEN-TODOS 21
/// / 22 / 23: "address book stays empty", "shows provisioned, not polled").
///
/// The Windows exe-name bootstrap always set it, so only setup-string clients were
/// affected — which is also why it was invisible on the machines that were provisioned
/// the old way.
pub const OPTION_MANAGEMENT_ENABLED: &str = "nemo-management-enabled";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SetupServer {
    #[serde(default)]
    pub id_server: String,
    #[serde(default)]
    pub relay_server: String,
    #[serde(default)]
    pub api_server: String,
    /// The server's Ed25519 identity key, base64. One value, two option names on this
    /// side: `key` (rendezvous handshake, signed id/pk) and `nemo-management-public-key`
    /// (signed policy).
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub api_cert_fingerprint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SetupBundle {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub issued_at: String,
    /// The dashboard address the operator generated it from. Logged on apply: a bundle
    /// made from a LAN dashboard session is the wrong one for a roaming machine, and
    /// afterwards this is the only clue that that is what happened.
    #[serde(default)]
    pub issued_from: String,
    /// "internal" (the server's LAN address) or "external" (its public one). The server
    /// exports both, and a client carries one: logged on apply, because a machine handed
    /// the wrong one of the two fails in a way that looks like a network fault, and this
    /// is the only record of which it was given.
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub server: SetupServer,
    /// The private half of a device key, when the bundle was generated together with
    /// one. Absent in the string an operator hands to an already-keyed machine.
    #[serde(default)]
    pub device_key: String,
}

/// Cheap shape test, so the import dialog can tell a setup string from a bare device key
/// without trying to decode either. Deliberately permissive: anything that LOOKS like a
/// bundle goes to `parse_setup`, which explains precisely what is wrong with it.
pub fn looks_like_setup(text: &str) -> bool {
    let text = text.trim();
    text.starts_with(SETUP_PREFIX)
        || text.starts_with("tbfdesk-setup-")
        || (text.starts_with('{') && text.contains("\"server\""))
}

/// Parse and VALIDATE. Accepts the string form, with or without the prefix, and the raw
/// JSON — the file an operator downloads is the string, but a hand-edited or
/// re-serialized one should not fail for a cosmetic reason.
pub fn parse_setup(text: &str) -> ResultType<SetupBundle> {
    let text = text.trim();
    if text.is_empty() {
        bail!("nothing to import");
    }
    let json = if text.starts_with('{') {
        text.as_bytes().to_vec()
    } else {
        let payload = text.strip_prefix(SETUP_PREFIX).unwrap_or_else(|| {
            // A prefix from another version: report it as that, not as "bad base64".
            text.split_once(':').map(|(_, rest)| rest).unwrap_or(text)
        });
        // Whitespace is what a paste out of a terminal or an email carries.
        let payload: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
        decode64(payload.as_bytes())
            .map_err(|_| hbb_common::anyhow::anyhow!(
                "this is not a TBFDesk setup string (it is not valid base64). Copy the \
                 whole string, including the tbfdesk-setup-v1: prefix."
            ))?
    };
    let bundle: SetupBundle = serde_json::from_slice(&json).map_err(|e| {
        hbb_common::anyhow::anyhow!("this setup string is damaged or incomplete ({})", e)
    })?;
    if bundle.v > 1 {
        bail!(
            "this setup string was made by a newer server (format v{}); update this \
             client, or generate a v1 string",
            bundle.v
        );
    }
    let s = &bundle.server;
    if s.id_server.trim().is_empty() {
        bail!("this setup string names no ID server");
    }
    let api = s.api_server.trim();
    if !(api.starts_with("http://") || api.starts_with("https://")) {
        bail!("this setup string's api-server is not an http(s) URL: {}", api);
    }
    // The identity key is the whole point of the bundle; a wrong one locks the client out
    // of the fleet in a way that reads as "server unreachable", so check it here.
    if crate::common::get_rs_pk(s.key.trim()).is_none() {
        bail!("this setup string's server key is not a valid Ed25519 public key");
    }
    if !bundle.device_key.trim().is_empty()
        && !crate::common::nemo_device_key_candidate_valid(bundle.device_key.trim())
    {
        bail!("this setup string carries a device key that is not valid");
    }
    Ok(bundle)
}

/// Marker: this machine's server settings came from a setup string the operator
/// imported, which therefore OUTRANKS the `host=…,key=…,relay=…` values baked into the
/// exe's file name.
///
/// Without it, a client installed from such a name is permanently locked to it:
/// `ui_interface::set_option` silently discards the four server keys
/// (`nemo_is_server_config_key`) and `nemo_preserve_locked_server_options` re-writes
/// them on every `set_options`, so a setup string applied exactly the two values that
/// are not in that list and nothing else — reported as "the setup string imports the ID
/// server and nothing else". Importing one is a deliberate re-provisioning, so it wins;
/// the exe name remains what provisions a machine nobody has imported anything into.
pub const OPTION_SETUP_OVERRIDES_EXE: &str = "nemo-setup-overrides-exe-name";

/// Per-key result of an apply. `refused` is the one that matters: a half-applied bundle
/// leaves a machine pointed at one server with another server's key, and until now that
/// happened silently.
#[derive(Clone, Debug, Default)]
pub struct SetupOutcome {
    /// What changed, human-readable, for the dialog and the log.
    pub applied: Vec<String>,
    /// What the client would not store, each with the reason. Non-empty means this
    /// machine is NOT fully provisioned, however green the dialog looks.
    pub refused: Vec<String>,
}

impl SetupOutcome {
    pub fn is_complete(&self) -> bool {
        self.refused.is_empty()
    }
}

/// Heading the dialog and the log put in front of `SetupOutcome::refused`, kept here so
/// the UI and the tests agree on the one string an operator searches for.
pub const REFUSED_HEADING: &str = "NOT applied — this client is not fully provisioned:";

/// Why a write did not stick. The answer is almost always "the server pushes this key
/// as a fixed global default", which is invisible from the client's own settings and is
/// the one thing the operator has to be told, because the fix is on the server.
fn refusal_reason(key: &str, wanted: &str) -> String {
    let pushed = hbb_common::config::OVERWRITE_SETTINGS
        .read()
        .map(|m| m.get(key).cloned())
        .unwrap_or_default();
    match pushed {
        Some(pushed) if pushed.trim() != wanted => format!(
            "{}: NOT applied — your server pushes this as a FIXED global default ({}). \
             Clear it in the dashboard (ACL & Policy → Global client defaults) or this \
             client keeps the pushed value.",
            key, pushed
        ),
        Some(_) => format!(
            "{}: pushed by the server as a fixed global default, same value — nothing to do.",
            key
        ),
        None => format!(
            "{}: NOT applied — the client refused to store it. Check that settings are \
             not disabled on this machine.",
            key
        ),
    }
}

/// Apply it to this client's config. Returns what changed and what would not — a
/// provisioning step that silently succeeds is impossible to support over the phone, and
/// one that silently half-succeeds is worse.
///
/// Every value is written through `Config::set_option`, the same path the settings
/// dialog and the licence-name bootstrap use, so there is no second mechanism to keep in
/// step. An absent field is left alone rather than cleared: a bundle with no device key
/// must not un-provision a machine that already has one. Each write is then READ BACK:
/// `Config::set_option` is a silent no-op for any key the server pushes as a fixed
/// default (`is_option_can_save`), so "I wrote it" and "it is stored" are different
/// facts and only the second one is worth reporting.
pub fn apply_setup(bundle: &SetupBundle) -> SetupOutcome {
    let s = &bundle.server;
    let mut out = SetupOutcome::default();
    {
        let out = &mut out;
        let mut set = |key: &str, value: &str, label: &str| {
            let value = value.trim();
            if value.is_empty() {
                return;
            }
            let old = Config::get_option(key);
            Config::set_option(key.to_owned(), value.to_owned());
            // Read back rather than trust the write.
            if Config::get_option(key).trim() != value {
                out.refused.push(refusal_reason(key, value));
                return;
            }
            if old.trim() == value {
                return;
            }
            out.applied.push(if old.trim().is_empty() {
                format!("{}: {}", label, value)
            } else {
                // The re-pointing case, which is the one worth seeing in a log.
                format!("{}: {} (was {})", label, value, old.trim())
            });
        };
        set("custom-rendezvous-server", &s.id_server, "ID server");
        set("api-server", &s.api_server, "api-server");
        set("nemo-management-server", &s.api_server, "management server");
        set("key", &s.key, "server key");
        set("nemo-management-public-key", &s.key, "management key");
        set("relay-server", &s.relay_server, "relay");
        set(
            "nemo-api-cert-fingerprint",
            &s.api_cert_fingerprint,
            "certificate pin",
        );
        // A bundle names a management server, so the machine is managed: turn the poll
        // on. Leaving it off produced a client that was configured for this fleet and
        // never spoke to it.
        set(OPTION_MANAGEMENT_ENABLED, "Y", "managed policy poll");
    }
    // The exe-name override, written whenever a bundle really did re-point this client.
    // It must be in place BEFORE anything calls set_options again, or the locked-exe
    // preservation puts the old server back.
    if !out.applied.is_empty() {
        Config::set_option(OPTION_SETUP_OVERRIDES_EXE.to_owned(), "Y".to_owned());
        // And in THIS process: get_rendezvous_server() prefers the in-memory exe value
        // over custom-rendezvous-server, so without clearing it the imported ID server
        // is ignored until the next restart.
        if let Ok(mut exe) = hbb_common::config::EXE_RENDEZVOUS_SERVER.write() {
            if !exe.is_empty() {
                log::info!(
                    "TBFDesk setup string overrides the server baked into the exe name ({})",
                    exe
                );
                exe.clear();
            }
        }
    }
    // Last, so a failure anywhere above leaves the machine un-keyed rather than keyed
    // against a half-configured server.
    if !bundle.device_key.trim().is_empty() {
        let key = bundle.device_key.trim().to_owned();
        Config::set_option("nemo-device-key".to_owned(), key.clone());
        if Config::get_option("nemo-device-key").trim() == key {
            out.applied.push("device key imported".to_owned());
        } else {
            out.refused.push(refusal_reason("nemo-device-key", &key));
        }
    }
    log::info!(
        "TBFDesk setup string applied{}{}{}: {}{}",
        if bundle.label.is_empty() { String::new() } else { format!(" for '{}'", bundle.label) },
        match bundle.scope.as_str() {
            "internal" => " [inside the network]".to_owned(),
            "external" => " [from the internet]".to_owned(),
            other if !other.is_empty() => format!(" [{}]", other),
            _ => String::new(),
        },
        if bundle.issued_from.is_empty() {
            String::new()
        } else {
            format!(" (generated on {})", bundle.issued_from)
        },
        if out.applied.is_empty() {
            "nothing changed, this client was already configured this way".to_owned()
        } else {
            out.applied.join("; ")
        },
        if out.refused.is_empty() {
            String::new()
        } else {
            format!(" -- REFUSED: {}", out.refused.join("; "))
        }
    );
    out
}

/// Import from a string or a file path, for `--import-setup` and the UI's file picker.
pub fn import_setup(arg: &str) -> ResultType<SetupOutcome> {
    let bundle = parse_setup(&read_setup_arg(arg)?)?;
    Ok(apply_setup(&bundle))
}

/// The text behind one `--import-setup` value: `-` reads standard input (a piped string or
/// file), an existing file is read (the dashboard's `.tbfsetup` download), anything else is
/// the string itself. Deciding by "does this file exist" rather than by shape keeps a path
/// that happens to look like base64 working.
pub fn read_setup_arg(arg: &str) -> ResultType<String> {
    let arg = arg.trim();
    if arg == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
        if text.trim().is_empty() {
            hbb_common::bail!("--import-setup -: nothing arrived on standard input");
        }
        return Ok(text);
    }
    if let Ok(text) = std::fs::read_to_string(arg) {
        return Ok(text);
    }
    // H26: the value usually carries the device key, and argv is visible to every process
    // on the machine. Still accepted (runbooks use it), but never quietly.
    eprintln!(
        "warning: --import-setup with the setup string itself on the command line exposes \
         the device key in the process list and shell history; use a file or `-` (stdin)"
    );
    Ok(arg.to_owned())
}

/// Every value given to `--import-setup` in an argument list, in order. Repeatable, so a
/// setup string and a separately handed-out bare device key can go in one call.
pub fn import_setup_values(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--import-setup" {
            if let Some(v) = it.next() {
                if !v.trim().is_empty() {
                    out.push(v.clone());
                }
            }
        }
    }
    out
}

/// The options a bundle provisions, WITHOUT writing them anywhere -- for pushing straight
/// into the running service (unattended install). Same keys as apply_setup; empty values are
/// left out (an empty relay means "the server's own", which apply_setup leaves untouched
/// too), the override marker rides along, and the device key comes last.
pub fn setup_option_values(bundle: &SetupBundle) -> Vec<(String, String)> {
    let s = &bundle.server;
    let mut values: Vec<(String, String)> = Vec::new();
    let mut add = |key: &str, value: &str| {
        let value = value.trim();
        if !value.is_empty() {
            values.push((key.to_owned(), value.to_owned()));
        }
    };
    add("custom-rendezvous-server", &s.id_server);
    add("api-server", &s.api_server);
    add("nemo-management-server", &s.api_server);
    add("key", &s.key);
    add("nemo-management-public-key", &s.key);
    add("relay-server", &s.relay_server);
    add("nemo-api-cert-fingerprint", &s.api_cert_fingerprint);
    add(OPTION_MANAGEMENT_ENABLED, "Y");
    add(OPTION_SETUP_OVERRIDES_EXE, "Y");
    add("nemo-device-key", &bundle.device_key);
    values
}

/// The options behind one piece of provisioning text: a setup string/bundle, or a bare
/// device key (what the import dialog also accepts).
pub fn provisioning_values(text: &str) -> ResultType<Vec<(String, String)>> {
    let text = text.trim();
    if looks_like_setup(text) {
        return Ok(setup_option_values(&parse_setup(text)?));
    }
    if crate::common::nemo_device_key_candidate_valid(text) {
        return Ok(vec![("nemo-device-key".to_owned(), text.to_owned())]);
    }
    hbb_common::bail!("neither a TBFDesk setup string nor a device key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::encode64;

    fn encode(json: &str) -> String {
        format!("{}{}", SETUP_PREFIX, encode64(json.as_bytes()))
    }

    #[test]
    fn a_setup_string_is_recognised_without_being_decoded() {
        assert!(looks_like_setup(&encode("{}")));
        assert!(looks_like_setup("  tbfdesk-setup-v1:abc  "));
        assert!(looks_like_setup("{\"v\":1,\"server\":{}}"));
        // A bare device key is 44 base64 characters and must NOT be taken for a bundle,
        // or the import dialog would reject the thing it was written for.
        assert!(!looks_like_setup(
            "0wBNKVl1kVhcZ0TXFdvkxqV9yK0M2SnJwRkQ4Y3hJbWc9PQ=="
        ));
        assert!(!looks_like_setup(""));
    }

    // Everything that can be wrong with a pasted string, reported as itself rather than
    // as a decode failure - these messages are what a technician reads on the phone.
    #[test]
    fn parse_rejects_each_kind_of_bad_bundle_with_its_own_reason() {
        let err = |text: &str| parse_setup(text).unwrap_err().to_string();
        assert!(err("").contains("nothing to import"));
        assert!(err("tbfdesk-setup-v1:!!!!").contains("not valid base64"));
        assert!(err(&encode("not json at all")).contains("damaged or incomplete"));
        assert!(err(&encode("{\"v\":2,\"server\":{}}")).contains("newer server"));
        assert!(err(&encode("{\"v\":1,\"server\":{}}")).contains("no ID server"));
        assert!(err(&encode(
            "{\"v\":1,\"server\":{\"id_server\":\"h\",\"api_server\":\"h:21120\"}}"
        ))
        .contains("not an http(s) URL"));
        assert!(err(&encode(
            "{\"v\":1,\"server\":{\"id_server\":\"h\",\"api_server\":\"https://h\",\"key\":\"nope\"}}"
        ))
        .contains("not a valid Ed25519 public key"));
    }

    /// TODO 21: the setup string imported the ID server and nothing else.
    ///
    /// `Config::set_option` is a SILENT no-op for every key the server pushes as a fixed
    /// global default (`is_option_can_save`), so "we wrote six values" and "six values
    /// are stored" were different facts and the client only ever reported the first.
    /// A machine pointed at one server with another server's key then fails as "cannot
    /// reach the server", which looks like a network fault.
    ///
    /// This drives the read-back: with `api-server` pushed as fixed, the apply must
    /// report it as REFUSED and name the pushed value, instead of listing it as applied.
    #[test]
    fn a_value_the_server_pins_is_reported_as_refused_not_as_applied() {
        // apply_setup writes the process-global Config, which the rest of the suite
        // also reads; serialise against the other config tests and put every key back.
        let _config_guard = crate::common::lock_config_for_test();
        let touched: Vec<&str> = APPLIED_OPTION_KEYS
            .iter()
            .copied()
            .chain([OPTION_SETUP_OVERRIDES_EXE])
            .collect();
        let saved: Vec<(&str, String)> = touched
            .iter()
            .map(|k| (*k, Config::get_option(k)))
            .collect();
        struct Restore(Vec<(&'static str, String)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (k, v) in self.0.drain(..) {
                    Config::set_option(k.to_owned(), v);
                }
            }
        }
        let _restore = Restore(saved);

        let (pk, _sk) = hbb_common::sodiumoxide::crypto::sign::gen_keypair();
        let key = encode64(pk.as_ref());
        let bundle = SetupBundle {
            v: 1,
            server: SetupServer {
                id_server: "10.0.0.5".to_owned(),
                relay_server: "10.0.0.5".to_owned(),
                api_server: "https://10.0.0.5:21120".to_owned(),
                key,
                api_cert_fingerprint: "AA:BB".to_owned(),
            },
            ..Default::default()
        };
        // What a policy poll with allow_user_override=false leaves behind.
        hbb_common::config::OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .insert("api-server".to_owned(), "https://wrong:21120".to_owned());
        let out = apply_setup(&bundle);
        hbb_common::config::OVERWRITE_SETTINGS
            .write()
            .unwrap()
            .remove("api-server");

        assert!(
            !out.is_complete(),
            "a bundle that could not store api-server is not a successful import"
        );
        let refused = out.refused.join("\n");
        assert!(refused.contains("api-server"), "refused: {}", refused);
        assert!(
            refused.contains("https://wrong:21120"),
            "the operator has to be told WHICH value the server pushes: {}",
            refused
        );
        assert!(
            !out.applied.iter().any(|l| l.starts_with("api-server:")),
            "a refused key must never appear in the applied list: {:?}",
            out.applied
        );
        // The keys that are not pinned still land, so a partial refusal does not stop
        // the rest of the provisioning.
        assert_eq!(Config::get_option("custom-rendezvous-server"), "10.0.0.5");
        // And an import that changed anything claims the exe-name override, which is
        // what stops a locked-exe client reverting on the next set_options.
        assert_eq!(Config::get_option(OPTION_SETUP_OVERRIDES_EXE), "Y");
        // A bundle that names a management server must also switch the poll on, or the
        // machine is configured for a fleet it never talks to: no policy, no login
        // gate, no address book, no direct endpoints. Verified in the lab — a
        // setup-string client sat "online, device key good, never polled".
        assert_eq!(Config::get_option(OPTION_MANAGEMENT_ENABLED), "Y");
        assert!(APPLIED_OPTION_KEYS.contains(&OPTION_MANAGEMENT_ENABLED));
    }

    #[test]
    fn a_valid_bundle_parses_whitespace_prefix_and_raw_json_alike() {
        let (pk, _sk) = hbb_common::sodiumoxide::crypto::sign::gen_keypair();
        let key = encode64(pk.as_ref());
        let json = format!(
            "{{\"v\":1,\"label\":\"Reception\",\"issued_from\":\"10.0.0.5:21120\",\"scope\":\"internal\",\
              \"server\":{{\"id_server\":\"10.0.0.5\",\"relay_server\":\"\",\
              \"api_server\":\"https://10.0.0.5:21120\",\"key\":\"{}\",\
              \"api_cert_fingerprint\":\"AA:BB\"}}}}",
            key
        );
        let from_string = parse_setup(&encode(&json)).unwrap();
        assert_eq!(from_string.server.id_server, "10.0.0.5");
        assert_eq!(from_string.label, "Reception");
        assert_eq!(from_string.scope, "internal");
        // An older bundle has no scope at all, which must parse rather than fail: the
        // field only feeds a log line.
        assert_eq!(
            parse_setup(&encode(&json.replace("\"scope\":\"internal\",", "")))
                .unwrap()
                .scope,
            ""
        );
        // The same string broken across lines by an email client.
        let wrapped = encode(&json);
        let wrapped = format!("{}\n{}", &wrapped[..20], &wrapped[20..]);
        assert_eq!(parse_setup(&wrapped).unwrap().server.key, key);
        // And the raw JSON, for a hand-edited or re-serialized file.
        assert_eq!(parse_setup(&json).unwrap().server.key, key);
    }
}

// Unattended provisioning (`--silent-install --import-setup`, `--import-setup` on an
// installed client): the values are computed without writing anything and pushed into the
// running service.
#[cfg(test)]
mod unattended_tests {
    use super::*;
    use crate::common::encode64;
    use hbb_common::sodiumoxide::crypto::sign;

    fn device_key() -> String {
        let (_, sk) = sign::gen_keypair();
        encode64(sk.as_ref())
    }

    fn bundle_string(relay: &str, dk: &str) -> String {
        let (pk, _) = sign::gen_keypair();
        let json = serde_json::json!({
            "v": 1, "scope": "internal",
            "server": {"id_server": "10.0.0.5", "relay_server": relay, "api_server": "https://10.0.0.5:21121",
                       "key": encode64(pk.as_ref()), "api_cert_fingerprint": "AB:CD"},
            "device_key": dk,
        });
        format!("{}{}", SETUP_PREFIX, encode64(json.to_string().as_bytes()))
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn import_setup_values_collects_every_value_in_order() {
        let a = strs(&["--silent-install", "--import-setup", "pc1.tbfsetup", "--debug", "--import-setup", "-"]);
        assert_eq!(import_setup_values(&a), ["pc1.tbfsetup", "-"]);
        assert!(import_setup_values(&strs(&["--silent-install"])).is_empty());
        assert!(import_setup_values(&strs(&["--import-setup"])).is_empty(), "flag without a value");
        assert!(import_setup_values(&strs(&["--import-setup", "  "])).is_empty(), "blank value");
    }

    #[test]
    fn setup_option_values_match_what_the_gui_import_provisions() {
        let dk = device_key();
        let values = setup_option_values(&parse_setup(&bundle_string("", &dk)).unwrap());
        let keys: Vec<&str> = values.iter().map(|(k, _)| k.as_str()).collect();
        // The GUI re-sends APPLIED_OPTION_KEYS (+ the override marker); the unattended path
        // must provision the same set, or the two would configure machines differently.
        for k in &keys {
            assert!(APPLIED_OPTION_KEYS.contains(k) || *k == OPTION_SETUP_OVERRIDES_EXE, "{k} not in APPLIED_OPTION_KEYS");
        }
        assert!(!keys.contains(&"relay-server"), "an empty relay leaves the existing one alone");
        assert_eq!(values.last().unwrap(), &("nemo-device-key".to_owned(), dk), "device key last");
        let get = |k: &str| values.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("custom-rendezvous-server"), Some("10.0.0.5"));
        assert_eq!(get("nemo-management-server"), Some("https://10.0.0.5:21121"));
        assert_eq!(get(OPTION_MANAGEMENT_ENABLED), Some("Y"));
        assert_eq!(get(OPTION_SETUP_OVERRIDES_EXE), Some("Y"));
        let with_relay = setup_option_values(&parse_setup(&bundle_string("10.0.0.5:21117", "")).unwrap());
        assert!(with_relay.iter().any(|(k, v)| k == "relay-server" && v == "10.0.0.5:21117"));
        assert!(!with_relay.iter().any(|(k, _)| k == "nemo-device-key"), "no device key in the bundle, none pushed");
    }

    #[test]
    fn provisioning_values_take_a_bundle_or_a_bare_device_key_and_refuse_the_rest() {
        let dk = device_key();
        assert_eq!(provisioning_values(&dk).unwrap(), vec![("nemo-device-key".to_owned(), dk.clone())]);
        assert!(provisioning_values(&bundle_string("", &dk)).unwrap().len() >= 8);
        assert!(provisioning_values("not a key").is_err());
        assert!(provisioning_values(&bundle_string("", "")[..30]).is_err(), "a truncated paste is refused");
    }

    #[test]
    fn read_setup_arg_reads_a_file_or_takes_the_string() {
        let dir = std::env::temp_dir().join(format!("tbf-setup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pc1.tbfsetup");
        std::fs::write(&f, "tbfdesk-setup-v1:abc\n").unwrap();
        assert_eq!(read_setup_arg(f.to_str().unwrap()).unwrap().trim(), "tbfdesk-setup-v1:abc");
        assert_eq!(read_setup_arg("  tbfdesk-setup-v1:inline  ").unwrap(), "tbfdesk-setup-v1:inline");
        std::fs::remove_dir_all(&dir).ok();
    }
}
