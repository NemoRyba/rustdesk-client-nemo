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

- the **Client setup string** block gives the strings on their own (for a machine whose
  key already exists), each with *Copy string* and *Download file* (a `.tbfsetup` text
  file);
- **generating a device key** returns the same bundles **with that key inside them**,
  which is the whole provisioning run: generate on the server, paste on the machine.

### Two of them: inside and outside

The server has two addresses, and a client carries **one** set, so the dashboard exports
both profiles side by side:

| | **Inside the network (LAN)** | **From the internet (public)** |
|---|---|---|
| for | workstations and technicians on the server's own network | roaming laptops, home offices |
| prefilled from | the address the dashboard is being read on, else the server's `--local-ip` | the server's `-r` relay address |
| relay in the bundle | the LAN address, so an internal session does not hairpin out through the router and back | empty — the server hands out its own public relay at runtime |
| file name | `…-setup-lan.tbfsetup` | `…-setup-wan.tbfsetup` |

Hand over the one that matches **where that machine connects from**. The wrong one fails
in a way that looks like a network fault: a workstation given the public address relays
out and back in through the router, and a roaming laptop given the LAN address cannot
reach the server at all. Which profile a machine was given is recorded in its own log
(`[inside the network]` / `[from the internet]` on the "setup string applied" line),
because afterwards that is the only way to tell.

The public profile is deliberately **not** derived from the dashboard address — an
operator administering over the LAN would otherwise bake a LAN address into the
"from the internet" string. If the server does not know its own public address it hands
back an empty profile asking for it, rather than a wrong one.

For a machine that is on both sides at different times, neither profile is really right:
the fix is one **split-horizon DNS name** resolving to each address from each side, which
makes the two strings identical. See `TOPOLOGY-DEPLOYMENT.md` in the superproject.

All the fields in both blocks are editable before anything is generated.

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
