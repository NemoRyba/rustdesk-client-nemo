# Nemo Management Client

This is a Nemo-specific feature behind the `nemo-management-client` Cargo
feature. It is enabled in the default build and can be removed for debugging by
building without default features or reverting this commit.

The Sciter client adds a separate `Management` entry next to `ID/Relay Server`.
It stores:

- `nemo-management-enabled`
- `nemo-management-server`
- `nemo-management-public-key`

When enabled, the controlled-side RustDesk service polls:

```text
{management-server}/nemo/api/client/policy
```

If the stored public key is set, the client requires the server response to
contain a valid signed payload from the hbbs key. If the public key is empty,
the client applies the unsigned payload for early lab testing.

The first managed controls reuse existing RustDesk host-side settings:

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

Future work: replace polling with a mutually authenticated encrypted control
channel if we need low-latency commands or richer device integrations.
