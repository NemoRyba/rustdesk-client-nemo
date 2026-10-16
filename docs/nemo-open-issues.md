# Open issues — client

Found on the Windows test workstation, 2026-10-16, build `11c4cac`, against the live lab
server. The full register, with the server-side items and the evidence, is
`OPEN-TODOS.md` in the superproject (`rustdesk-nemo-flavour`); the numbers match.

**Before investigating 21 or 22:** the tested build predates
`3467315 fix(setup import): propagate to the service over IPC`. Retest on a build that
includes it — part of the symptom may already be gone.

## 🔴 21. A setup string applies the ID server and nothing else  *(CRITICAL)*

Importing a setup string **with** a device key leaves the client with
`custom-rendezvous-server` set and `relay-server`, `api-server` and the server `key`
unset. The only route that works today is: import the bare device key, then type the
server settings in by hand.

`apply_setup` (`src/nemo_setup.rs`) writes all of them through `Config::set_option`, so
check the **file** first — `tbfdesk --option api-server`, and
`%APPDATA%\RustDesk\config\RustDesk2.toml`. If the file is right and the UI is wrong,
there are two candidates and they are easy to tell apart:

1. **The locked-exe guard — prime suspect.** `ui_interface::set_option` returns silently
   when `nemo_exe_custom_server_configured()` and the key is in `NEMO_SERVER_CONFIG_KEYS`
   (`src/ui_interface.rs:83`): `custom-rendezvous-server`, `relay-server`, `api-server`,
   `key`, `nemo-company-network-only`. A client installed from a
   `rustdesk-host=…,key=…,relay=….exe` file name is permanently in that state, and
   `nemo_preserve_locked_server_options` re-writes those keys on every `set_options`.
   That is a 1:1 match for the four values that go missing — and it means the IPC
   propagation added in `3467315` drops exactly them.
   **Decide, do not half-apply:** either refuse a setup string on a locked-exe client
   with a message naming the host its file name locks it to, or treat an imported bundle
   as an explicit override of the exe name.
2. **The policy poll overwrites it.** `api-server` is also a *Global client defaults* key
   pushed from the dashboard; with `allow_user_override=false` it becomes a fixed option,
   `is_option_fixed` then makes `set_option` a no-op and `nemo_restore_fixed_options`
   re-inserts the server's value. Check what that dashboard field contains — the
   deployment doc says to leave it empty while LAN and WAN clients use different
   addresses.

**Acceptance:** one paste on a clean Windows client leaves all six values set, surviving a
service restart and a policy poll, with nothing typed by hand.

## 🔴 22. The address book stays empty after an import  *(CRITICAL)*

Probably downstream of 21 (no `api-server` → no `/api/ab/get`), but confirm in this
order before assuming: `api-server` correct → signed in (the address book needs a login
token) → `nemo-ab-version` arriving in the policy poll → `getAb()` firing. If it is still
empty with all four right, it is its own bug.

## 🔴 26. "Load from file…" in the import dialog is misaligned  *(CRITICAL by request)*

In `open_import_device_key_dialog` (`src/ui/index.tis`) the button sits in its own `<div>`
inside `.form .set-password`, whose CSS lays out label/input pairs — so the button lands
in the label column instead of under the field. Give the row the same shape as the input
row (an empty label cell, or a class that spans both columns) and check it at both dialog
widths.

## Related, tracked on the server side

- **23** a connected client reads *provisioned, not polled* in the dashboard — correct as
  written (the label comes from the management poll, not the rendezvous handshake), and a
  symptom of 21.
- **24** the Relayed-bytes panel calls relayed sessions "went direct" when it has no data
  from hbbr.
- **25** *Cut* blocks the peer instead of only ending the session.
