# xcut-android

Prototipe Android: kontrol ARP (`cut`/`uncut`) via Shizuku — tanpa root,
menggunakan izin ADB shell (uid 2000).

## Dependensi (terbaru per saat ini)

| Library | Versi |
|---|---|
| `dev.rikka.shizuku:api` | **13.1.5** |
| `dev.rikka.shizuku:provider` | **13.1.5** |
| AGP | 8.7.3 |
| Kotlin | 2.1.0 |
| compileSdk / minSdk | 35 / 26 |

## Build

1. Install **Shizuku** di HP: https://shizuku.rikka.app/ — aktifkan via
   `adb wireless debugging` (tanpa root) atau root.
2. Buka folder ini di **Android Studio** (biarkan gradle sync + wrapper dibuat),
   lalu Run ke device yang Shizuku-nya sudah aktif.
3. Di app: **Minta izin Shizuku** -> **Cek status + capability** -> **Scan**.

## Yang jalan / tidak

| Fitur | Status | Keterangan |
|---|---|---|
| Scan neighbor | ✅ | baca tabel `ip neigh` (read-only) |
| `cut` | ⚠️ tergantung device | `ip neigh replace ... nud permanent` butuh **CAP_NET_ADMIN** — panel capability menampilkan apakah device kamu punya |
| `uncut` | ⚠️ sama | `ip neigh del` |
| deauth (monitor mode) | ❌ | stack Wi-Fi Android (vendor HAL) tidak expose nl80211 monitor mode |
| BLE spam | ✅ **tanpa root & tanpa Shizuku** | engine `BleSpammer` (API `BluetoothLeAdvertiser` standar): rotasi payload cepat 20-30ms — Fast Pair / Apple Continuity / generic churn. MAC tetap dikelola stack |

## BLE Spam (v1.2+)

- **Tanpa root, tanpa Shizuku** — murni Android API (mirror konsep dari proyek blespam GPL-3.0, ditulis ulang dari nol sehingga bebas lisensi)
- Butuh runtime izin: `BLUETOOTH_CONNECT` + `BLUETOOTH_ADVERTISE`
- Tiga mode: **Fast Pair** (popup Google), **Continuity** (popup AirPods), **generic churn** (UUID random)
- Batasan platform: MAC tidak bisa di-set manual; beberapa device menolak dengan `ADVERTISE_FAILED_FEATURE_UNSUPPORTED`

## Phase 2 (kalau lanjut)

- Backend ARP raw socket via **NDK** (butuh `CAP_NET_RAW` saja — lebih banyak
  device yang punya daripada `NET_ADMIN`): kirim crafted ARP reply agar
  device mengarah ke MAC non-existent.
- Fallback otomatis: deteksi CapEff dulu, pilih `ip neigh` vs raw socket.

## Catatan

Mirror dari `xcut` Linux (ARP) yang diadaptasi ke Android. Kernel deps
(`iw`, `aircrack-ng`, dll.) tidak relevan — semua lewat command Android.
