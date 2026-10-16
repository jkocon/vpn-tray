#!/usr/bin/env bash
# Instaluje/aktualizuje vpn-tray w systemie. Uruchom jako root (sudo -A ./install.sh).
# Działający tray podmienia się dopiero po ponownym zalogowaniu (albo: pkill -x vpn-tray; /usr/local/lib/vpn-tray/vpn-tray &).
# Zastępuje osobne traye (tailscale-, twingate-, netbird-, wireguard-tray): usuwa ich autostart,
# skróty i reguły polkit; ich binarki zostają w /usr/local/lib (powrót = ich własny install.sh).
# Kod wyjścia 10 = brak jakiegokolwiek VPN-a, nic nie zainstalowano.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
LIB=/usr/local/lib/vpn-tray
OLD=(tailscale-tray twingate-tray netbird-tray wireguard-tray)
[[ $EUID -eq 0 ]] || { echo "Uruchom przez sudo"; exit 1; }

if ! command -v tailscale >/dev/null && ! command -v twingate >/dev/null &&
   ! command -v netbird >/dev/null && ! command -v nmcli >/dev/null; then
    echo "vpn-tray: brak Tailscale, Twingate, NetBird i NetworkManagera - pomijam"
    exit 10
fi

# wireguard-tools: tunele wg-quick (import z traya tworzy je zamiast połączeń NetworkManagera).
pacman -S --needed --asdeps --noconfirm kdialog wl-clipboard libnotify xdg-utils wireguard-tools

BIN=$("$SRC/build.sh" "$SRC")

install -Dm755 "$BIN" "$LIB/vpn-tray"
# Pomocnik roota dla tuneli wg-quick (pkexec); właściciel root, żeby nikt go nie podmienił.
install -Dm755 -o root -g root "$SRC/wg-helper" "$LIB/wg-helper"
rm -rf "$LIB/icons"
install -Dm644 -t "$LIB/icons" "$SRC"/icons/*.svg
install -Dm644 -t /etc/xdg/autostart "$SRC/vpn-tray.desktop"
install -Dm644 "$SRC/vpn-tray-launcher.desktop" /usr/local/share/applications/vpn-tray.desktop
install -Dm644 "$SRC/vpn-tray.svg" /usr/local/share/icons/hicolor/scalable/apps/vpn-tray.svg
gtk-update-icon-cache -qtf /usr/local/share/icons/hicolor 2>/dev/null || true
install -Dm644 "$SRC/49-vpn-tray.rules" /etc/polkit-1/rules.d/49-vpn-tray.rules

# Stare osobne traye: bez autostartu, skrótów i reguł (inaczej dwie ikony na jeden VPN).
for old in "${OLD[@]}"; do
    rm -f "/etc/xdg/autostart/$old.desktop" "/usr/local/share/applications/$old.desktop" \
          "/etc/polkit-1/rules.d/49-$old.rules"
done

# Zmiana ustawień Tailscale z traya bez roota wymaga operatora (pierwszy zwykły użytkownik).
user=$(getent passwd 1000 | cut -d: -f1)
if command -v tailscale >/dev/null && [[ -n $user ]] && systemctl is-active --quiet tailscaled; then
    tailscale set --operator="$user" || echo "vpn-tray: nie udało się ustawić operatora Tailscale"
fi

# CLI netbird domyślnie szuka /var/run/netbird.sock; pakiet netbird-bin uruchamia netbird@<iface>
# z socketem /var/run/netbird/<iface>.sock - zmienna dla terminali w sesji (tray wykrywa socket sam).
unit=$(systemctl list-unit-files --plain --no-legend 'netbird@*.service' 2>/dev/null | awk '$2=="enabled"{print $1; exit}')
if [[ -n $unit && $unit =~ ^netbird@(.+)\.service$ ]]; then
    install -d /etc/environment.d
    echo "NB_DAEMON_ADDR=unix:///var/run/netbird/${BASH_REMATCH[1]}.sock" > /etc/environment.d/50-netbird.conf
fi
