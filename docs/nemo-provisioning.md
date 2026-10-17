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

1. **The gate / settings dialog** — *Import setup string or device key*. The one field
   takes **either** a bare device key **or** a setup string; an operator handed one string
   should not have to know which kind it is. On success the dialog says what changed, and
   the applied values are pushed to the running service over IPC, so the live client
   adopts the new server and key immediately instead of at the next restart.
   The field is plain text, not masked: Sciter's masked input eats Ctrl+V
   (`OPEN-TODOS` 16), and a setup string is far too long to retype.
2. **Load from file…** in that dialog — pick the `.tbfsetup` downloaded from the
   dashboard. Nothing to paste at all, which is also the route to use if the clipboard
   is unavailable (an RDP session without clipboard redirection, a locked-down desktop).
3. **Unattended:** `tbfdesk --import-setup <file|string>`. Runs before any UI exists and
   prints what it changed. Under `sudo` it writes the *user's* config, not root's. No IPC
   push is needed or possible here — the service reads the config when it starts.

A bundle with no device key in it does **not** clear a key the machine already has, and
the device key is written last — a failure anywhere leaves the machine un-keyed rather
than keyed against a half-configured server.

### What is refused, and why that matters

Each of these has its own message, because the message is what gets read out over the
phone: not valid base64 (a truncated copy), damaged or incomplete JSON, a bundle from a
**newer** server (format `v2+`), no ID server, an `api-server` that is not an `http(s)`
URL, a server key that is not a valid Ed25519 public key, and a device key that does not
pass the same check the key field applies. Nothing is applied unless all of it passes.

## Removing the settings again (Windows)

Where they are, because the client writes two copies and the second one is the one people
miss:

| Path | Whose |
|---|---|
| `%APPDATA%\TBFDesk\config\` | the signed-in user's client |
| `C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\TBFDesk\config\` | the **service** (`--server`), which keeps its own copy and syncs over IPC |

In each: `TBFDesk.toml` (ID, keypair, permanent password), `TBFDesk2.toml` (**every**
option — the device key `nemo-device-key`, the server addresses, the identity key, the
certificate pin), `TBFDesk_local.toml` (local state incl. the login token),
`TBFDesk_status.toml`, `TBFDesk_lan_peers.toml`, plus `peers\*.toml`, the
`TBFDesk_ab` / `TBFDesk_group` caches, and `%APPDATA%\TBFDesk\log\`.

**On a machine upgraded from 1.4.7 there is a third and a fourth copy**, the
`…\RustDesk\config\` directory of each profile. Since 1.4.8 `APP_NAME` is `TBFDesk` and a
first start migrates a RustDesk-named config into the new location (RENAMING-PLAN Layer 2
— the copy is deliberate, it is the rollback path). That means **clearing only the TBFDesk
directories does not reset the machine**: the next start migrates the old identity straight
back in. Clear all four, which is what the script below does.

### Reset the settings, keep the install

Elevated PowerShell. Also in the superproject as
`scripts/reset-windows-client-config.ps1`, which is the maintained copy — use it rather
than pasting this:

```powershell
foreach ($n in @('TBFDesk','RustDesk')) { Stop-Service $n -Force -EA 0 }
Start-Sleep 2
foreach ($d in @("$env:APPDATA\TBFDesk\config", "$env:APPDATA\RustDesk\config",
                 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\TBFDesk\config',
                 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config')) {
  if (Test-Path $d) { Get-ChildItem $d -Filter *.toml | % { Copy-Item $_.FullName "$($_.FullName).bak" -Force; Remove-Item $_.FullName -Force } }
}
Start-Service TBFDesk; (Get-Service TBFDesk).Status
```

It clears the `*.toml` in all four directories and leaves a `.bak` of each. It does
**not** touch `peers\*.toml` (a subdirectory, so the filter does not match it), the
`TBFDesk_ab` / `TBFDesk_group` caches (no `.toml` extension), the logs, or anything
outside the config directories.

Three things to know afterwards:

- **The backups are secrets.** `RustDesk2.toml.bak` still contains the device key — this
  machine's Layer 1 identity — and `RustDesk.toml.bak` its keypair. That is exactly what
  you want for a repair; for a decommission, delete them.
- **The machine comes back with a new TBFDesk ID**, because the keypair is regenerated on
  the next start.
- **So the server now has a key bound to an ID that no longer exists.** Clear or re-point
  that key's *Bound to ID* in the dashboard, or delete it and issue a new one; with
  first-use claiming on, clearing the binding re-arms it and the machine's next attempt
  files a fresh claim. Then import a setup string as above.

### Remove everything (decommission)

Uninstall first (`tbfdesk --uninstall`, or Apps & Features). That removes the install
directory, the Start-menu folder and shortcuts (both the old `RustDesk*` and the current
`TBFDesk*` names), the uninstall registry key, the `HKCR\.rustdesk` / `HKCR\rustdesk`
entries, the `RustDesk` service, the `RustDesk Service` firewall rule, the printer
driver, the Amyuni IDD and the test certificates. It deliberately does **not** remove the
config, so that a reinstall keeps the ID and password. Then, elevated:

```cmd
rd /s /q "%APPDATA%\RustDesk"
rd /s /q "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk"
rd /s /q "C:\Users\Public\Documents\RustDesk"
rd /s /q "%ProgramFiles%\RustDesk"
reg delete "HKCU\Software\Classes\rustdesk" /f 2>nul
```

Run the `%APPDATA%` line for **every** user profile that ran the client
(`C:\Users\*\AppData\Roaming\RustDesk`), not just the one you are signed in as. The
`Public\Documents\RustDesk` directory is the custom-client staging dir, which the
uninstaller leaves on purpose. Installers downloaded by the updater sit in `%TEMP%`.

### The tray menu

Right-clicking the tray icon offers **Open**, **Stop service** and **Exit**. They are
three different things: *Stop service* stops the background service and with it
unattended access (the machine stops being reachable); *Exit* closes only the tray icon
and leaves the service running — it returns the next time the client starts. A reset like
the one above stops and starts the service itself, so neither entry is needed for it.

## Afterwards

- The client's *Server* field on the login gate is prefilled from `api-server`, so a
  provisioned machine shows the right address without being told it twice.
- If the key is **unbound** and first-use claiming is on, the client is still refused
  until an operator approves the claim in the dashboard, and says so:
  *"Waiting for approval by your administrator"*. See `DEVICE-KEY-CLAIM.md` in the
  superproject.
- To re-point a machine at a different server, import that server's bundle: every value
  above is overwritten, and the log line records what each one was before.
