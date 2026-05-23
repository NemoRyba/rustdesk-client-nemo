# Nemo GUI Server Settings

This fork adds a small server-mode layer around RustDesk's existing
`ID/Relay Server` settings.

Normal executable launches keep the upstream behavior: the Sciter GUI reads and
writes these persisted options across launches:

- `custom-rendezvous-server`
- `relay-server`
- `api-server`
- `key`
- `nemo-company-network-only`

When the Windows executable name contains custom server data, for example
`rustdesk-host=192.168.0.176,key=...,.exe`, that executable configuration stays
higher priority than the saved GUI settings. In this mode the GUI shows
`ID/Relay Server (locked)` and opens a read-only information dialog instead of
allowing edits. Attempts to change the same server keys through the Sciter
settings path are ignored so the user's normal saved GUI profile is not
overwritten by a locked executable launch.

The `Company network only` checkbox is available only for normal editable GUI
settings. It requires an ID server and blocks explicit public RustDesk network
targets such as `id@public`. A locked custom-server executable also blocks
`id@public` so the executable's server priority cannot be bypassed from the
remote ID field.

To disable the GUI feature without removing code, set this constant in
`src/ui/index.tis`:

```tiscript
const nemo_gui_server_settings = false;
```

To remove the feature during debugging, revert the commit that introduced this
file and the matching changes in `src/ui/index.tis`, `src/common.rs`,
`src/client.rs`, `src/ui_interface.rs`, and `libs/hbb_common/src/config.rs`.
