# vpn-tray

**Jedna ikona w zasobniku dla wszystkich VPN-ów** – Tailscale, Twingate, NetBird i WireGuard
(połączenia NetworkManagera) – i **zawsze tylko jeden VPN włączony**. Wybierasz sieć z listy:
tray rozłącza to, co działa, i łączy wybraną.

> **English documentation:** [README.md](README.md)

Zastępuje osobne [tailscale-tray](https://github.com/jkocon/tailscale-tray),
[twingate-tray](https://github.com/jkocon/twingate-tray),
[netbird-tray](https://github.com/jkocon/netbird-tray) i
[wireguard-tray](https://github.com/jkocon/wireguard-tray) – każdy z nich jest teraz podmenu.
VPN-a, którego nie ma w systemie, nie ma w menu.

## Menu

- **Lista wyboru:** *None* + każde konto Tailscale i Twingate, każdy profil NetBird (np. „dom”,
  „firma”) i każde połączenie WireGuard. Wybór = rozłączenie pozostałych VPN-ów, potem połączenie
  wybranego (ze zmianą konta/profilu i logowaniem w przeglądarce, jeśli trzeba).
- **Więcej niż jeden VPN włączony** (np. dwa demony z autostartu): ostrzeżenie i *Keep only …*.
- **WireGuard w sieci, w której jesteś:** jeśli komputer ma już adres w podsieciach tunelu,
  tray pyta przed połączeniem.
- **Ikona:** ikona aktywnego VPN-a z jego stanami; szara tarcza, gdy wszystko wyłączone.
- **Podmenu** każdego VPN-a: wszystko, co miały osobne traye (urządzenia, sieci, exit node,
  konta/profile, ustawienia, import .conf…).

## Wiersz poleceń

```sh
vpn-tray --only netbird           # tylko jeden VPN (jak dawne osobne traye)
vpn-tray --switch netbird:firma   # przełączenie bez menu - skróty klawiszowe, skrypty
vpn-tray --switch wireguard:kurant
vpn-tray --switch none            # wszystko wyłączone
vpn-tray --dump                   # menu jako tekst (testy)
```

## Instalacja

```sh
sudo ./install.sh
```

Buduje jako zwykły użytkownik, instaluje do `/usr/local/lib/vpn-tray/` z autostartem, skrótem,
ikoną i regułą polkit `49-vpn-tray.rules`. Usuwa autostart, skróty i reguły starych osobnych
trayów (ich binarki zostają). Kod wyjścia 10 = brak obsługiwanego VPN-a.

## Licencja

MIT
