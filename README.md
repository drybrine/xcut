# xcut

Alat penguji jaringan: **Wi-Fi cut/deauth**, **BLE advertising spoof**, dan **BLE soft-jam** — berjalan di Linux lewat MGMT control channel (tanpa perlu mematikan bluetoothd).

> Hanya untuk uji di jaringan yang **kamu miliki atau sudah diizinkan**. Penggunaan yang tidak berizin adalah ilegal di banyak negara.

## Fitur

- `scan` / `list` — menemukan perangkat aktif di subnet
- `cut` / `uncut` / `stop` — blokir perangkat lewat ARP spoofing (tidak menembus AP isolation)
- `deauth <nr|ip|all>` — tendang perangkat dari Wi-Fi via monitor mode (`aireplay-ng`, butuh `aircrack-ng`), diakhiri dengan `deauth stop`
- `exclude` — daftar perangkat yang dilewati dari `cut all` / `deauth all`
- `ble spam` — spoof advertising BLE (AirPods, AirTag, Samsung, dll.) lewat MGMT channel
- `ble burst` / `ble jam` — adv-churn flood (discovery denial) + connect-flood per-device (`bluetoothctl`)

## Installation

```bash
mkdir -p ~/.local/bin
install -m755 xcut xcut-ble xcut-ble-raw ~/.local/bin/
sudo pacman -S --noconfirm aircrack-ng      # untuk sub-perintah 'deauth' (aireplay-ng)
```

## Cara pakai

```bash
xcut scan                 # pindai perangkat di subnet
xcut list                 # tampilkan hasil scan (bernomer)
xcut cut 5                # blokir perangkat nomor 5
xcut uncut 5              # lepas blokir
xcut stop                 # restore semua

xcut deauth all           # kick semua client Wi-Fi (wifi Anda ikut putus sementara)
xcut deauth stop          # hentikan deauth & kembalikan interface

xcut exclude              # daftar perangkat dikecualikan
xcut exclude 7            # tambahkan perangkat 7 ke daftar pengecualian
xcut exclude -7           # hapus dari daftar

xcut ble scan             # scan perangkat BLE di sekitar
xcut ble on all           # spoof berbagai advertising BLE secara bersamaan
xcut ble jam <MAC>        # soft-jam: burst global + connect-flood target
xcut ble jam stop         # hentikan semua
```

> Perintah butuh root — `xcut` otomatis meminta sudo saat diperlukan.

## Struktur

| File           | Peran                                                    |
|----------------|----------------------------------------------------------|
| `xcut`         | CLI utama: scan / cut / deauth / stop / exclude / ble   |
| `xcut-ble`     | Orkestrator BLE: on / off / check / scan / burst / jam   |
| `xcut-ble-raw` | Engine python MGMT control channel (advertising + burst) |

## Catatan

- `ble jam` adalah *soft-jam* (flood iklan + connect flood), bukan RF jammer sungguhan; adaptor ini tak bisa memancarkan sinyal jam radio.
- Nama `xcut` dibuat custom → unik.