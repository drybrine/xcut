# xcut

Alat penguji jaringan: **Wi-Fi cut/deauth**, **BLE advertising spoof**, dan **BLE soft-jam** — berjalan di Linux lewat MGMT control channel (tanpa perlu mematikan bluetoothd).

> Hanya untuk uji di jaringan yang **kamu miliki atau sudah diizinkan**. Penggunaan yang tidak berizin adalah ilegal di banyak negara.

## Fitur

- `scan` / `list` — menemukan perangkat aktif di subnet (kolom vendor OUI otomatis)
- `scan -w` / `--watch` — pindai berulang, tampilkan diff perangkat baru/hilang
- `scan --v6` — selain ARP, ikut mendeteksi neighbor IPv6 (NDP)
- `list` / `scan` dengan `--json` — output JSON untuk scripting
- `status` — ringkasan: jumlah perangkat, yang sedang diblokir, status deauth
- `cut` / `uncut` / `stop` — blokir perangkat lewat ARP spoofing (tidak menembus AP isolation); Ctrl+C saat `cut all` otomatis merestore semua
- `deauth <nr|ip|all>` — tendang perangkat dari Wi-Fi via monitor mode (`aireplay-ng`, butuh `aircrack-ng`), diakhiri dengan `deauth stop`
- `exclude` — daftar perangkat yang dilewati dari `cut all` / `deauth all`
- `ble spam` — spoof advertising BLE (AirPods, AirTag, Samsung, dll.) lewat MGMT channel
- `ble burst` / `ble jam` — adv-churn flood (discovery denial) + connect-flood per-device (`bluetoothctl`)

## Persyaratan (dependencies)

**Wajib** — dipakai oleh sub-perintah tertentu:

| Paket (Arch)       | Tool            | Dipakai untuk                          |
|--------------------|-----------------|----------------------------------------|
| `iproute2`         | `ip`            | semua operasi (interface, route, neigh)|
| `iputils`          | `ping`, `arping`| scan fallback & restore koneksi        |
| `dsniff`           | `arpspoof`      | `cut` / `uncut` / `stop` (ARP spoof)   |
| `iw`               | `iw`            | `deauth` (monitor mode, channel)       |
| `aircrack-ng`      | `aireplay-ng`   | `deauth` engine utama                  |
| `NetworkManager`   | `nmcli`         | kelola interface & ganti band (`DEAUTH_SEQ`) |
| `python3`          | python3         | engine BLE (`xcut-ble-raw`)            |
| `bluez`            | `bluetoothctl`  | `ble scan` / `ble jam`                 |

**Opsional** — terdeteksi otomatis jika terpasang, hasil lebih baik:

| Paket (Arch)       | Tool         | Kegunaan                                 |
|--------------------|--------------|------------------------------------------|
| `arp-scan`         | `arp-scan`   | scan menemukan device yang tak balas ping|
| `mdk4`             | `mdk4`       | engine deauth alternatif (`DEAUTH_ENGINE=mdk4`) |
| `ethtool`          | `ethtool`    | deteksi driver wireless fallback         |
| `wpa_supplicant`   | `wpa_cli`    | cek proteksi 802.11w (PMF) AP            |

## Installation

**Otomatis (semua distro Linux)** — script installer mendeteksi paket manager
(`pacman`/`apt`/`dnf`/`zypper`/`apk`), install dependency, dan pasang tools:

```bash
./install.sh               # Arch: sudo pacman -S ...; salin ke ~/.local/bin
./install.sh --system      # pasang ke /usr/local/bin
./install.sh --no-deps     # hanya salin tools (dependency sudah ada)
./install.sh --deps-only   # hanya install dependency
```

**Manual (Arch):**

```bash
mkdir -p ~/.local/bin
install -m755 xcut xcut-ble xcut-ble-raw ~/.local/bin/

# semua dependensi wajib + opsional dalam sekali perintah (Arch)
sudo pacman -S --noconfirm iproute2 iputils dsniff iw aircrack-ng \
     networkmanager python bluez arp-scan mdk4 ethtool wpa_supplicant
```

**Engine BLE via pip** (opsional, pengganti salinan manual `xcut-ble-raw`):

```bash
pip install .              # atau: pipx install .
```

`xcut-ble` otomatis memakai `xcut-ble-raw` dari PATH bila ada.

**Instalasi via npm** (seluruh toolkit, butuh Node.js):

```bash
npm install -g .           # dari folder repo ini
```

Bisa juga di-publish ke registry: `npm publish` (sudah ada `package.json` dengan
mapping `bin`). Dependency kernel tetap wajib — `./install.sh --deps-only`.

> Windows/macOS **tidak didukung** — tools ini butuh akses kernel Linux
> (raw socket, monitor mode Wi-Fi, MGMT channel BLE).

## Cara pakai

```bash
xcut scan                 # pindai perangkat di subnet
xcut scan -w              # watch mode: pindai tiap 15 detik, tampilkan perangkat baru/hilang
xcut scan --v6            # sertakan neighbor IPv6 (NDP)
xcut scan --json          # hasil scan sebagai JSON
xcut list                 # tampilkan hasil scan (bernomer)
xcut list --json          # hasil scan terakhir sebagai JSON
xcut status               # apa yang sedang diblokir + status deauth
xcut status --json
xcut cut 5                # blokir perangkat nomor 5
xcut uncut 5              # lepas blokir
xcut stop                 # restore semua

xcut deauth all           # kick all client Wi-Fi (WiFi Anda mungkin tersendat/stutter)
xcut deauth stop          # hentikan deauth & kembalikan interface
DEAUTH_SEQ=1 xcut deauth all   # kick SEMUA band AP dual-band, bergantian
                               # (2.4G -> 5G -> ulang; khusus kartu bawaan iwlwifi)

xcut exclude              # daftar perangkat dikecualikan
xcut exclude 7            # tambahkan perangkat 7 ke daftar pengecualian
xcut exclude -7           # hapus dari daftar

xcut ble scan             # scan perangkat BLE di sekitar
xcut ble on all           # spoof berbagai advertising BLE secara bersamaan
xcut ble conn all         # iklan CONNECTABLE (ADV_IND): perangkat sekitar
                          # dikirimi prompt koneksi ke payload palsu (request-conn spam)
xcut ble jam <MAC>        # soft-jam: burst global + connect-flood target
xcut ble jam stop         # hentikan semua
```

> Perintah butuh root — `xcut` otomatis meminta sudo saat diperlukan
> (`list`, `status`, dan `ble scan` tidak butuh root).

## Testing

```bash
./tests/run.sh             # install bats + pytest (jika belum ada) lalu jalankan semua test
./tests/run.sh --no-deps   # hanya jalankan test (tanpa install)
```

- `tests/xcut.bats` — unit test bash (resolve target, exclude, freq2ch, vendor OUI, JSON, status) — tanpa root & tanpa hardware
- `tests/test_ble_raw.py` — unit test engine BLE (payload adv, format, batas 31 byte)

## Env

| Variabel       | Fungsi                                    |
|----------------|-------------------------------------------|
| `WATCH_EVERY`  | interval `scan -w` (detik, default 15)    |
| `XCUT_NAMES=0` | matikan lookup nama (getent/avahi)        |
| `NO_COLOR`     | matikan warna output                      |
| `XCUT_CACHE_DIR` | lokasi cache state (default `~/.local/share/xcut`) |

## Struktur

| File           | Peran                                                    |
|----------------|----------------------------------------------------------|
| `xcut`         | CLI utama: scan / cut / deauth / stop / exclude / ble   |
| `xcut-lib/`    | Pustaka bersama: `vendor.sh` (OUI), `wifi.sh` (netinfo/neigh), `deauth.sh` (engine deauth) |
| `xcut-ble`     | Orkestrator BLE: on / off / check / scan / burst / jam   |
| `xcut-ble-raw` | Engine python MGMT control channel (advertising + burst) |

## Catatan

- `ble jam` adalah *soft-jam* (flood iklan + connect flood), bukan RF jammer sungguhan; adaptor ini tak bisa memancarkan sinyal jam radio.
- Nama `xcut` dibuat custom → unik.