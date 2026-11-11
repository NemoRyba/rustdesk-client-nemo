// TBFDesk: patched copy of termios 0.2.2 -- Android uses the Linux termios layout
// (bionic). Needed because portable-pty -> serial -> serial-unix pulls this version in,
// and the console (terminal) service is built for Android since 1.4.21.
//! OS-specific definitions.

#[cfg(any(target_os = "linux", target_os = "android"))] pub use self::linux as target;
#[cfg(target_os = "macos")] pub use self::macos as target;
#[cfg(target_os = "freebsd")] pub use self::freebsd as target;
#[cfg(target_os = "openbsd")] pub use self::openbsd as target;

#[cfg(any(target_os = "linux", target_os = "android"))] pub mod linux;
#[cfg(target_os = "macos")] pub mod macos;
#[cfg(target_os = "freebsd")] pub mod freebsd;
#[cfg(target_os = "openbsd")] pub mod openbsd;
