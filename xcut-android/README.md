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
| ADB bootstrap (v1.3+) | ✅ **tanpa root, tanpa Shizuku** | pairing wireless debugging in-app (SPAKE2 + TLS 1.3), key disimpan, daemon `xcutd` di-push & start sebagai uid shell |
| Scan neighbor | ✅ | daemon raw socket (baca → kirim ARP request broadcast) |
| `cut` | ✅ tanpa Shizuku | daemon `xcutd` AF_PACKET spoof — butuh shell uid (didapat via adb bootstrap) |
| BLE spam | ✅ tanpa izin apa pun | engine `BleSpammer` (API `BluetoothLeAdvertiser`) |
| deauth (monitor mode) | ❌ | stack Wi-Fi Android (vendor HAL) tidak expose nl80211 monitor mode |

## ADB bootstrap (v1.3+) — pengganti Shizuku

Flow: **Wireless Debugging di Settings** → app cari mDNS endpoint pairing → masukkan 6-digit code → app jalanin protokol pairing (TLS 1.3 + SPAKE2-Ed25519 + AES-GCM, ported from BoringSSL/adb source) → push `xcutd` binary → start sebagai shell uid → semua raw socket berjalan.

- Hanya **Android 11+** (wireless debugging). Android 10 ke bawah: fallback Shizuku.
- Alur ini sudah diuji end-to-end di JVM (TLS asli + semua lapisan crypto) — test device masih perlu manual.
- Detil protokol & file reference: `pairing_connection.cpp`, `spake25519.cc` (BoringSSL), `aes_128_gcm.cpp` (AOSP adb).

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
