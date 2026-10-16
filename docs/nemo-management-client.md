# Nemo Management Client

This is a Nemo-specific feature behind the `nemo-management-client` Cargo
feature. It is enabled in the default build and can be removed for debugging by
building without default features or reverting this commit.

The Sciter client adds a separate `Management` entry next to `ID/Relay Server`.
It stores:

- `nemo-management-enabled`
- `nemo-management-server`
- `nemo-management-public-key`
- `nemo-outbound-enabled`
- `nemo-outbound-targets`

When enabled, the controlled-side RustDesk service polls:

```text
{management-server}/nemo/api/client/policy
```

If the stored public key is set, the client requires the server response to
contain a valid signed payload from the hbbs key. If the public key is empty,
the client applies the unsigned payload for early lab testing.

Managed controls reuse existing RustDesk setting keys. By default the server is
authoritative: policy values are inserted into RustDesk's fixed setting maps,
so the GUI treats those controls as locked and local writes are ignored. If the
server policy sets `allow_user_override` to `true`, the values become defaults
instead and users may override them locally.

The quick controls include:

- `enable-keyboard`
- `enable-clipboard`
- `enable-file-transfer`
- `enable-camera`
- `enable-terminal`
- `enable-audio`
- `enable-tunnel`
- `enable-remote-restart`
- `enable-record-session`
- `enable-block-input`
- `enable-privacy-mode`
- `enable-remote-printer`
- `allow-remote-config-modification`
- `enable-lan-discovery`
- `nemo-outbound-enabled`
- `nemo-outbound-targets`

`nemo-outbound-enabled=N` disables outgoing connections in the Sciter main
window and in the Rust connection path. `nemo-outbound-targets` limits outgoing
connections to exact target IDs separated by comma, semicolon, or whitespace;
`*` allows every target.

Updated clients also identify their local TBFDesk ID and UUID during rendezvous, which
lets hbbs reject a blocked controller or a disallowed target before the connection
reaches the password prompt.

**Changed 2026-10-16 (OPEN-TODOS 8):** that identity now travels in a real protobuf
field, `NemoSource {id, uuid, token}` on `PunchHoleRequest` and `RequestRelay`, in the
forked `hbb_common`. It used to be smuggled inside `PunchHoleRequest.version` and
`RequestRelay.licence_key` precisely to keep the upstream schema unchanged — which also
meant every controller gate depended on the server carving up a string, and a client that
left the marker out read as "anonymous" rather than as a protocol error. The client sends
both for now, and the server prefers the field, so an un-updated peer on either end keeps
working. Either way the identity is **asserted, not proved**: what proves a controller is
the device-key handshake, which the server prefers over both.

How a fresh client gets configured in the first place — the device key and the one-paste
setup string — is in [`nemo-provisioning.md`](nemo-provisioning.md).

The advanced policy editor can also set other recognized global, local, and
display option keys such as server settings, proxy settings, theme/language,
codec/FPS/display preferences, approval mode, auto update, whitelist, and
recording options.

Future work: replace polling with a mutually authenticated encrypted control
channel if we need low-latency commands or richer device integrations.
