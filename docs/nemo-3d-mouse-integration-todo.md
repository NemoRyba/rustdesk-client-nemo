# Nemo 3D Mouse Integration TODO

Goal: merge the existing separate VPN-based 3D AutoCAD mouse transport into the
Nemo RustDesk client so workstation users get one remote-work package.

TODO:

- Document the current standalone 3D mouse program protocol, ports, device
  discovery, and authentication assumptions.
- Identify where the RustDesk client captures and forwards local input events.
- Decide whether 3D mouse data should travel through the RustDesk session
  channel, a Nemo side channel, or the existing VPN route during the first
  integration phase.
- Add a client-side capability flag so the server/admin UI can show whether a
  peer supports Nemo 3D mouse forwarding.
- Add GUI status only after the data path is proven stable.
- Keep the integration behind a separate Nemo feature commit and runtime switch
  so remote desktop performance can be debugged without the 3D mouse layer.

Non-goal for the first pass: rewriting the working standalone transport before
we have measured the RustDesk session path under AutoCAD workload.
