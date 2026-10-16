# First-run provisioning (device key + setup string)

What a technician does on a machine that has just had the client installed, and what the
client actually writes when they do it.

## Why there is anything to do at all

Layer 1 makes a provisioned **device key** mandatory: without one the client renders the
*provisioning gate* and nothing else — no ID panel, no connect field, no address book —
and the server refuses its settings poll, its address-book fetch and its login. A client
also cannot find the server by itself. Six values have to be right first:

| Option | What it is |
|---|---|
| `custom-rendezvous-server` | the ID / rendezvous server (`host` or `host:port`) |
| `relay-server` | the relay. Empty is fine: hbbs hands out its own `-r` at runtime |
| `api-server` | the management API URL (login, address book) |
| `nemo-management-server` | the same URL — the signed policy poll |
| `key` | the server's Ed25519 identity key, base64 |
| `nemo-management-public-key` | the same key — verifies signed policy |

plus `nemo-api-cert-fingerprint` when the API serves a self-signed certificate, and
`nemo-device-key` for the key itself. Most are base64 and all are exact; one wrong
character fails as *"cannot reach the server"*, which looks exactly like a network fault.

## The setup string

The dashboard hands all of it over as one value:

```text
tbfdesk-setup-v1:<base64 of a small JSON object>
```

It is produced in **Settings → Device keys**:

- the **Client setup string** block gives the string on its own (for a machine whose key
  already exists), with *Copy string* and *Download file* (a `.tbfsetup` text file);
- **generating a device key** returns the same bundle **with that key inside it**, which
  is the whole provisioning run: generate on the server, paste on the machine.

The three server fields in that block are prefilled from the address the operator is
reading the dashboard on, and are editable — a LAN address is wrong for a machine that
will connect from outside, and the client gets no second chance to guess.

> **It is the client's trust anchor, not a convenience file.** The identity key inside is
> what this machine will verify the server with from then on, so a bundle from the wrong
> hands points the machine at the wrong server. It is deliberately **unsigned**: what a
> signature would be checked against is the key inside it. Move it the way you would move
> a password. The same has always been true of the `host=..,key=..` exe name.

## Importing it

Three routes, all landing in the same code (`src/nemo_setup.rs`):

1. **The gate / settings dialog** — *Import device key*. The one field takes **either** a
   bare device key **or** a setup string; an operator handed one string should not have to
   know which kind it is. On success the dialog says what changed.
2. **Load from file…** in that dialog — pick the `.tbfsetup` downloaded from the
   dashboard. Also the route that works while Ctrl+V is broken in that masked field
   (`OPEN-TODOS` 16).
3. **Unattended:** `tbfdesk --import-setup <file|string>`. Runs before any UI exists and
   prints what it changed. Under `sudo` it writes the *user's* config, not root's.

A bundle with no device key in it does **not** clear a key the machine already has, and
the device key is written last — a failure anywhere leaves the machine un-keyed rather
than keyed against a half-configured server.

### What is refused, and why that matters

Each of these has its own message, because the message is what gets read out over the
phone: not valid base64 (a truncated copy), damaged or incomplete JSON, a bundle from a
**newer** server (format `v2+`), no ID server, an `api-server` that is not an `http(s)`
URL, a server key that is not a valid Ed25519 public key, and a device key that does not
pass the same check the key field applies. Nothing is applied unless all of it passes.

## Afterwards

- The client's *Server* field on the login gate is prefilled from `api-server`, so a
  provisioned machine shows the right address without being told it twice.
- If the key is **unbound** and first-use claiming is on, the client is still refused
  until an operator approves the claim in the dashboard, and says so:
  *"Waiting for approval by your administrator"*. See `DEVICE-KEY-CLAIM.md` in the
  superproject.
- To re-point a machine at a different server, import that server's bundle: every value
  above is overwritten, and the log line records what each one was before.
