# RustDesk Guide

## Project Layout

### Directory Structure
* `src/` Rust app
* `src/server/` audio / clipboard / input / video / network
* `src/platform/` platform-specific code
* `src/ui/` legacy Sciter UI (deprecated)
* `flutter/` current UI
* `libs/hbb_common/` config / proto / shared utils
* `libs/scrap/` screen capture
* `libs/enigo/` input control
* `libs/clipboard/` clipboard
* `libs/hbb_common/src/config.rs` all options

### Key Components
- **Remote Desktop Protocol**: Custom protocol implemented in `src/rendezvous_mediator.rs` for communicating with rustdesk-server
- **Screen Capture**: Platform-specific screen capture in `libs/scrap/`
- **Input Handling**: Cross-platform input simulation in `libs/enigo/`
- **Audio/Video Services**: Real-time audio/video streaming in `src/server/`
- **File Transfer**: Secure file transfer implementation in `libs/hbb_common/`

### UI Architecture
- **Legacy UI**: Sciter-based (deprecated) - files in `src/ui/`
- **Modern UI**: Flutter-based - files in `flutter/`
  - Desktop: `flutter/lib/desktop/`
  - Mobile: `flutter/lib/mobile/`
  - Shared: `flutter/lib/common/` and `flutter/lib/models/`

## Rust Rules

* Avoid `unwrap()` / `expect()` in production code.
* Exceptions:

  * tests;
  * lock acquisition where failure means poisoning, not normal control flow.
* Otherwise prefer `Result` + `?` or explicit handling.
* Do not ignore errors silently.
* Avoid unnecessary `.clone()`.
* Prefer borrowing when practical.
* Do not add dependencies unless needed.
* Keep code simple and idiomatic.

## Tokio Rules

* Assume a Tokio runtime already exists.
* Never create nested runtimes.
* Never call `Runtime::block_on()` inside Tokio / async code.
* Do not hide runtime creation inside helpers or libraries.
* Do not hold locks across `.await`.
* Prefer `.await`, `tokio::spawn`, channels.
* Use `spawn_blocking` or dedicated threads for blocking work.
* Do not use `std::thread::sleep()` in async code.

## Editing Hygiene

* Change only what is required.
* Prefer the smallest valid diff.
* Do not refactor unrelated code.
* Do not make formatting-only changes.
* Keep naming/style consistent with nearby code.

## TBFDesk: both UIs ship (parity rule)

This fork ships the **Sciter** UI (`src/ui/`, `src/ui.rs`, `src/ui/remote.rs`) and the
**Flutter** UI (`flutter/`, `src/flutter_ffi.rs`, `src/flutter.rs`) in parallel; machines
switch from one to the other one by one. Until Sciter is retired:

* Every user-visible change, feature or fix goes into **both** UIs in the same branch —
  Flutter desktop and, where it applies, Flutter mobile (Android). A Sciter-only or
  Flutter-only change is incomplete.
* Every menu entry, input field and setting must exist in both and do the same thing
  (same option key and value, same locked/managed greying, same validation). The element
  checklist is `FLUTTER-PARITY-ELEMENTS.md` in the superproject; the `parity` test stage
  fails when a Sciter element has no Flutter line.
* Record the change as a row in the superproject's `FLUTTER-PORT.md` §5 and test it in
  both UIs — including the multi-display modes (single / all / span / windows) on two
  monitors: multi-monitor is the normal case for TBFDesk users.
* FFI: `src/flutter_ffi.rs` functions are thin wrappers over the same Rust function the
  Sciter binding calls — no logic in the FFI layer, no Rust logic re-implemented in Dart.
