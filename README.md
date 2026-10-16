# vpn-tray

**One system tray icon for all your VPNs** – Tailscale, Twingate, NetBird and WireGuard
(NetworkManager connections) – with **only one VPN on at a time**. Pick a network from the list:
the tray disconnects whatever else is on and connects the one you chose.

> **Polish documentation:** [README.pl.md](README.pl.md)

It replaces the separate [tailscale-tray](https://github.com/jkocon/tailscale-tray),
[twingate-tray](https://github.com/jkocon/twingate-tray),
[netbird-tray](https://github.com/jkocon/netbird-tray) and
[wireguard-tray](https://github.com/jkocon/wireguard-tray): each of them lives on as a submenu.
A VPN that is not installed simply does not appear.

---

## Menu

The menu opens on a left **or** right click:

```
VPN: NetBird – dom
──────────
( ) None (all off)
( ) Tailscale – you@example.com       ← one entry per account
( ) Twingate
(o) NetBird – dom                     ← one entry per NetBird profile
( ) NetBird – work
( ) WireGuard – office  (vpn.example.com)   ← one entry per WireGuard connection
──────────
○ Tailscale  (disconnected)   ▸   devices, exit nodes, accounts, settings…
○ Twingate   (disconnected)   ▸   resources, exit networks, accounts…
● NetBird    (dom: connected) ▸   devices, networks, exit nodes, profiles…
○ WireGuard  (disconnected)   ▸   tunnel details, import .conf, manage connections
──────────
About / Exit
```

- **Switching:** choose an entry → every other VPN is disconnected, then the chosen one connects
  (switching account / profile first if needed, starting a browser login when the account is
  logged out). *None* turns everything off.
- **More than one VPN on** (e.g. two daemons autostarted at boot): the menu warns and offers
  *Keep only …*.
- **WireGuard on its own LAN:** if this computer already has an address inside a WireGuard
  tunnel's subnets (you are on that network), the tray asks before connecting.
- **WireGuard without clutter:** *Import a .conf file…* creates a **wg-quick** tunnel
  (`/etc/wireguard/<name>.conf`, root-only; service `wg-quick@<name>`), not a NetworkManager
  connection – so it does not show up in the desktop's network applet while it is off. The
  bundled `wg-helper` does the root part via pkexec (no password for `wheel`); it reads the file
  with your permissions and refuses `PreUp`/`PostUp`-style commands. Existing NetworkManager
  WireGuard connections keep working and are marked *[NM]*.
- **Icon:** the icon of the active VPN with its usual states (connected, exit node, sign-in
  needed, server not answering); a grey shield when everything is off.

The submenus keep everything the separate trays had – see their READMEs for details.

## Command line

```sh
vpn-tray                          # the tray
vpn-tray --only netbird           # only one VPN (like the old separate trays)
vpn-tray --switch netbird:work    # switch without the menu – for keyboard shortcuts and scripts
vpn-tray --switch wireguard:office
vpn-tray --switch none            # everything off
vpn-tray --dump                   # print the menu once (testing)
```

`--switch` matches the account / profile / connection by name prefix; an unknown name prints
the available ones.

## Requirements

- Linux desktop with a **StatusNotifierItem** tray (KDE Plasma; GNOME with the AppIndicator extension).
- Any of: **Tailscale** (`tailscaled`), **Twingate** (`twingate.service`), **NetBird**
  (`netbird.service` or `netbird@<iface>.service`), **wireguard-tools** (wg-quick) and/or **NetworkManager** 1.16+ for WireGuard.
- polkit and the `wheel` group: the bundled rule lets you start/stop Twingate and NetBird without a
  password; Tailscale needs you as operator (`install.sh` sets it); NetworkManager's own wheel rule
  covers WireGuard import/changes.
- Runtime helpers: `kdialog`, `notify-send` (libnotify), `xdg-open`, `wl-copy` (or `xclip`/`xsel`),
  a terminal (`konsole`, `alacritty`, `kitty` or `xterm`).
- To build: Rust 1.85+.

## Install

```sh
sudo ./install.sh
```

Builds as your user (never as root), installs to `/usr/local/lib/vpn-tray/`, adds autostart,
a launcher, the icon and `/etc/polkit-1/rules.d/49-vpn-tray.rules`. It removes the autostart
entries, launchers and polkit rules of the old separate trays (their binaries stay). Exit code 10
means no supported VPN is installed.

## License

MIT
