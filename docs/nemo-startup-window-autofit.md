# Nemo Startup Window Autofit

This fork adds a Windows-only startup sizing pass for the Sciter client window.

RustDesk normally restores the last saved main-window rectangle, or opens the
main window at its built-in default size. Long startup cards or status messages
can be clipped when that rectangle is too small. The Nemo pass measures the
initial rendered panes and only grows the window when the current size cannot
fit the startup content.

The pass is intentionally limited:

- it runs only on Windows Sciter UI startup;
- it only grows the initial window, never shrinks it;
- it runs three delayed checks during the first second, then stops;
- it does not touch remote-session rendering or the Flutter remote viewport.

To disable without removing code, set this constant in `src/ui/index.tis`:

```tiscript
const nemo_fit_initial_window_to_content = false;
```

To remove the feature during debugging, revert the commit that introduced this
file and the matching `src/ui/index.tis` change.
