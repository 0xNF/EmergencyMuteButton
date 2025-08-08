# tl;dr
Make sure your laptop never blasts your music when you unlock it.

Mutes your audio playback devices when you logon, logoff, lock, or unlock your computer. (via the Windows Event Log). 

# Summary
This tool, which is intended to run as a Windows Service, subscribes to the Windows Event Log and listens for event ids: `[4624, 4625, 4626, 4800, 4801, 4802, 4803]`. 
These events are defined as follows:
* 4624
  * An account was successfully logged on
* 4625
  * An account failed to log on
* 4626
  * User/Device claims information
    * In practice, this is for "new logons"
* 4800
  * The workstation was locked.
    * (ctrl-l)
* 4801
  * The workstation was unlocked.
* 4802
  * The screen saver was invoked
    * Not yet locked, but screensaver is on
* 4803
  * The screen saver was dismissed.

When received, the primary audio device is retrieved, and is set to `mute`.

Because Audting of `Other Logon/Logoff Events` (aka, 4800 and onwards) is not enabled by default on windows computers, this program also attempts, at startup time, to enable the audting of those events. This effectively uses the same APIs as the `secpol.msc` to do so.  

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