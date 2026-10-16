#!/usr/bin/env bash
# Buduje aplikację w Rust jako zwykły użytkownik (cargo nigdy jako root) i wypisuje ścieżkę binarki.
# Wołane z install.sh (jako root): BIN=$("$SRC/build.sh" "$SRC").
# Buduje użytkownik z sudo, a przy instalacji z cachyos_sync (target/apply.sh) - użytkownik cachyos-sync.
set -euo pipefail
crate=$(cd "$1" && pwd)
name=$(sed -n 's/^name = "\(.*\)"/\1/p' "$crate/Cargo.toml" | head -1)  # nazwa binarki z Cargo.toml
command -v cargo >/dev/null || pacman -S --needed --noconfirm rust >&2
cargo=(cargo build --release --locked --quiet --manifest-path "$crate/Cargo.toml")
if [[ $EUID -eq 0 ]]; then
    user=${SUDO_USER:-cachyos-sync}
    home=$(getent passwd "$user" | cut -d: -f6)
    [[ -n $home ]] || { echo "build.sh: brak użytkownika $user" >&2; exit 1; }
    target=$home/.cache/cachyos-sync-trays
    runuser -u "$user" -- env HOME="$home" CARGO_TARGET_DIR="$target" "${cargo[@]}" >&2
else
    target=$HOME/.cache/cachyos-sync-trays
    CARGO_TARGET_DIR="$target" "${cargo[@]}" >&2
fi
echo "$target/release/$name"
