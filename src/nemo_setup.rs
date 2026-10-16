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
];

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

/// Apply it to this client's config. Returns the human-readable summary of what changed,
/// for the dialog and the log — provisioning that silently succeeds is impossible to
/// support over the phone.
///
/// Every value is written through `Config::set_option`, the same path the settings
/// dialog and the licence-name bootstrap use, so there is no second mechanism to keep in
/// step. An absent field is left alone rather than cleared: a bundle with no device key
/// must not un-provision a machine that already has one.
pub fn apply_setup(bundle: &SetupBundle) -> Vec<String> {
    let s = &bundle.server;
    let mut applied = Vec::new();
    let mut set = |key: &str, value: &str, label: &str| {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        let old = Config::get_option(key);
        Config::set_option(key.to_owned(), value.to_owned());
        if old.trim() == value {
            return;
        }
        applied.push(if old.trim().is_empty() {
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
    // Last, so a failure anywhere above leaves the machine un-keyed rather than keyed
    // against a half-configured server.
    if !bundle.device_key.trim().is_empty() {
        Config::set_option(
            "nemo-device-key".to_owned(),
            bundle.device_key.trim().to_owned(),
        );
        applied.push("device key imported".to_owned());
    }
    log::info!(
        "TBFDesk setup string applied{}{}{}: {}",
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
        if applied.is_empty() {
            "nothing changed, this client was already configured this way".to_owned()
        } else {
            applied.join("; ")
        }
    );
    applied
}

/// Import from a string or a file path, for `--import-setup` and the UI's file picker.
pub fn import_setup(arg: &str) -> ResultType<Vec<String>> {
    let arg = arg.trim();
    // A path is the common case for the CLI (the dashboard's download), a string for a
    // paste. Deciding by "does this file exist" rather than by shape keeps a path that
    // happens to look like base64 working.
    let text = match std::fs::read_to_string(arg) {
        Ok(text) => text,
        Err(_) => arg.to_owned(),
    };
    let bundle = parse_setup(&text)?;
    Ok(apply_setup(&bundle))
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
