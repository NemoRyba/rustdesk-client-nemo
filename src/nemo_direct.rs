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

use hbb_common::{anyhow::anyhow, config::Config, log, ResultType};
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
pub const OPTION_KNOCK_KEY: &str = "nemo-knock-key";
/// base64 HMAC-SHA256 key, shared with the same fwknopd. SECRET.
pub const OPTION_KNOCK_HMAC_KEY: &str = "nemo-knock-hmac-key";
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
    OPTION_KNOCK_DELAY_MS,
    OPTION_KNOCK_USER,
    OPTION_KNOCK_SOURCE_IP,
];

const DEFAULT_KNOCK_PORT: u16 = 62201; // fwknopd's default
const DEFAULT_KNOCK_DELAY_MS: u64 = 300;
const DEFAULT_KNOCK_USER: &str = "tbfdesk";
const DEFAULT_KNOCK_SOURCE_IP: &str = "0.0.0.0";
/// Deliberately tight. A dead port forward must not add noticeable latency to a
/// connection that is about to succeed over the relay anyway.
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

pub fn direct_timeout() -> Duration {
    let ms = Config::get_option(OPTION_DIRECT_TIMEOUT_MS)
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|ms| *ms > 0)
        .unwrap_or(DEFAULT_DIRECT_TIMEOUT_MS);
    Duration::from_millis(ms)
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

/// Read the knock settings, or `None` when knocking is off or unusable.
///
/// A half-configured knock (enabled, no keys) returns `None` and logs: the connection
/// then goes out WITHOUT a knock, which either succeeds (the port was never gated) or
/// fails and falls back to the relay. Refusing to connect would be the wrong call —
/// the knock is a hardening layer over a port forward, not an authentication boundary
/// for the session itself. That boundary is the Ed25519 handshake, which runs either way.
pub fn knock_config() -> Option<KnockConfig> {
    if Config::get_option(OPTION_KNOCK_ENABLED) != "Y" {
        return None;
    }
    let key = decode_spa_key(&Config::get_option(OPTION_KNOCK_KEY), OPTION_KNOCK_KEY)?;
    let hmac_key = decode_spa_key(
        &Config::get_option(OPTION_KNOCK_HMAC_KEY),
        OPTION_KNOCK_HMAC_KEY,
    )?;
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
}
