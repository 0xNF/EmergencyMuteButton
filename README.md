# tl;dr
Make sure your laptop never blasts your music when you unlock it.

Mutes your audio playback devices when you logon, logoff, lock, or unlock your computer. (via the Windows Event Log). 
# Requirements

* Windows (not cross platform)
* Rust 1.80+
* Administrator privs

# Building

`cargo build`

# Running
Must run as an admin because of Event Log access

# Installing (manual)
## Install
1. `cargo run -- install`
2. `net start "EmergencyMuteButton"`

## Uninstall
1. `cargo run -- uninstall`
2. `net delete "EmergencyMuteButton"`


# Installing (msi)
1. `cargo wix`
2. then running `./target/wix/EmergencyMuteButton.msi`

This also sets the uninstaller in the Installed Applications menu under settings.


# See also:
https://github.com/mullvad/windows-service-rs
https://medium.com/@aleksej.gudkov/rust-windows-service-example-building-a-windows-service-in-rust-907be67d2287