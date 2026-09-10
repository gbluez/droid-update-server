# ANTIPAS - Complete Version & Release History

Dokumentasi riwayat rilis, fungsi, dan evolusi fitur aplikasi ANTIPAS sejak awal pengembangan.

---

## 🚀 Version 3.8.3 (2026-09-10) - *Latest Stable Release*

### 🛠️ Pemasangan & Pembaruan Driver Mobile Signed WHQL
- **Universal Mobile Driver Installer**: Menambahkan menu "Install Mobile Driver" di Reboot dropdown (indeks paling akhir di bawah separator) dan perintah CLI (`driver` / `install_driver`).
- **Cakupan Lengkap Virtual COM**: Pemasangan signed driver WHQL Windows untuk Qualcomm HS-USB QDLoader 9008, MediaTek Preloader/VCOM DA, Samsung Mobile USB Modem/CDC, Unisoc/Spreadtrum U2S Diag & Download Port, serta serial COM UART.
- **USB ADB & Fastboot Stack**: Sinkronisasi WinUSB composite endpoint dan Google/Kedacom Android Bootloader interface.
- **Pipeline 5-Tahap Informatif**: Audit hardware SetupAPI, re-enumerasi native PnP bus, pencocokan signature INF Driver Store, restart daemon ADB host bridge, dan auto-refresh matrix device tanpa log penutup ganda.

### 🌐 Network Sentinel & Auto-Update Engine
- **Diagnostik Jaringan Native**: Uji konektivitas internet ICMP ping (1.1.1.1 & 8.8.8.8) dengan penilaian latensi RTT dan rating kesehatan jaringan.
- **Uptime Probe GitHub**: Handshake TCP TLS port 443 dan pemeriksaan respons HTTP 200 OK endpoint GitHub.
- **Streaming Live Downloader**: Pengunduhan paket pembaruan chunked dengan visualisasi Unicode progress bar [████████░░░░] real-time dan perhitungan kecepatan live transfer (KB/s, MB/s).
- **1-Klik Deploy & Restart**: Pembuatan script otomatis `updates\apply_update.bat` untuk ekstraksi container ZIP dan relaunching otomatis.

### 💻 Antarmuka & Frame Jendela Dinamis
- **Universal Standby Reboot**: Menu Reboot kini selalu dapat diakses kapan saja meski tidak ada perangkat yang terhubung.
- **Format Judul Jendela Dinamis**: Windows title kini menampilkan versi aktif secara otomatis: `[3.8.3] Antipas - Hemodialyzer Built for Android Platform`.
- **Batas Ukuran Minimum GUI**: Mengunci batas ukuran minimum form pada 870 x 590 px (`WM_GETMINMAXINFO`) dengan layout responsif anti-overlapping.

---

## 📦 Version 3.8.2 (2026-09-05)

### 🛠️ Core Engine & ADB Bridge v2.0
- **Android 16 & Modern SDK Compatibility**: Perbaikan parsing output perintah `adb devices` dengan pembersihan karakter kontrol (`\r\n`), mencegah error status `offline`/`unauthorized` palsu.
- **Dynamic Binary Resolver**: Deteksi path `adb.exe` otomatis secara runtime relatif terhadap direktori aplikasi (`exeDir`), subdirektori `bin/`, atau system `PATH`.
- **Hardware Fallback Profiling**: Penambahan fallback `ro.product.marketname` dan `ro.product.model` untuk perangkat terbaru (HyperOS, Xiaomi 14/15/Redmi 15C).
- **Auto-Recovery Daemon**: Mekanisme auto-restart ADB server saat koneksi komunikasi ADB pipe terputus atau hung.

### 🧹 Fitur Baru: Remove BLOATWARE & Ads
- **1-Click Debloater**: Disediakan melalui tombol dropdown popup menu di bawah **ADB DIAG** dan command CLI (`bloatware` / `debloat`).
- **Pembersihan Iklan Xiaomi / HyperOS / MIUI**:
  - `com.miui.msa.global` (MIUI System Ads Daemon)
  - `com.miui.android.fashiongallery` (Glance Lockscreen Wallpaper Carousel)
  - `com.miui.analytics` & `com.miui.daemon` (Tracking & Telemetry)
- **Pembersihan Facebook Background Services**:
  - `com.facebook.appmanager`, `com.facebook.services`, `com.facebook.system`
- **Pembersihan Game & Partner Bloatware bawaan vendor**.

### 🛡️ Turbo-Parallel Malware Database Engine v5.6
- **Resolusi Crash PowerShell**: Memperbaiki runtime exception pada format tanggal .NET (`DateTimeOffset.Value` null reference error).
- **Migrasi Database Maltrail 7.12**: Terhubung ke repositori terdedikasi `stamparm/trails` dengan ekstraksi rekursif stream `ReadLines` berkecepatan tinggi.
- **Threat Intelligence RAT Feed 7.8**: Penggantian URL feed lama dengan repository aktif `Various-Malware-Hashes` (19.250+ IOC signatures).
- **Ekspansi Database**: Total mencapai **1.826.523 signature** keamanan dan **2.908.652 heuristic rules**.
- **Pre-bundled Distribution**: Database malware kini terdistribusi otomatis di folder `dist/malware/malwares.json`.

### 💳 Dukungan & Donasi
- Integrasi informasi donasi resmi untuk pengembangan tools:
  - **BCA**: `3200244329`
  - **DANA**: `0816990450`

---

## ⚡ Version 3.8.0 (2026-08-13)

### Fitur Utama
- **Public Freeware Edition**: Penghapusan pembatasan aktivasi hardware licensing untuk penggunaan bebas komunitas teknisi.
- **Multi-Source Security Cluster**: Integrasi feed Abuse.ch (MalwareBazaar), InQuest Labs, Maltrail Heuristics, dan MH-100K Dataset.
- **HTML5 Embedded Engine**: Penggantian komponen RichEdit lama dengan web browser host berbasis IE/Edge control untuk rendering telemetry interaktif.
- **Hardware Profiler**: Inspeksi real-time CPU architecture, logical core topology, physical RAM bus, dan disk space storage.

---

## 🔧 Version 3.7.0 (2026-07-20)

### Fitur Utama
- **Google Play Services Restoration Center**: Fitur cerdas 1-Klik Repair & Install Google Play Services & Play Store yang secara otomatis mendeteksi versi SDK Android target.
- **Samsung Expert Tools**: Modul bypass FRP helper, Factory Reset, dan Reboot Download Mode via ADB raw socket.
- **Live Telemetry Streamer**: Integrasi progress bar visual interaktif dan event logger real-time.

---

## 🔍 Version 3.6.0 (2026-06-10)

### Fitur Utama
- **Forensic Deep Inspector**: Analisis metadata paket APK, permissions security mapping, dan hidden system services.
- **OTA Killer Daemon**: Fitur disable Google & vendor OTA system update otomatis untuk mencegah locking vendor.
- **Extended ADB Shell CLI**: Konsol interaktif terintegrasi dengan command autocomplete dan auto-linkification URL/file path.

---

## 🏗️ Version 3.5.0 (2026-05-02)

### Fitur Utama
- **Major Rebranding**: Perubahan nama proyek dari **DROID** menjadi **ANTIPAS Platform**.
- **Modular DLL Architecture**: Pemisahan modul inti menjadi dynamic library `antipas_adb.dll`, `browser_host.c`, dan `security.c`.
- **Turbo-Parallel Synchronizer v5.5**: Mesin multi-thread downloader dataset ancaman keamanan via PowerShell background jobs.
- **Build System Modern**: Penambahan otomasi kompilasi menggunakan `build.bat` dan Makefile dengan optimasi compiler `-O2`.

---

## 📦 Version 3.0.0 (2026-01-15)

### Fitur Utama
- **Initial Stable GUI Release**: Antarmuka Windows Native modern dengan Dark Cyberpunk Theme.
- **Core Forensic Engine**: Deteksi hardware motherboard serial, CPU, RAM, Disk topology, dan validasi device Android.
- **Multi-Device Discovery**: Manajemen switching perangkat ADB aktif secara simultan.

---

## 🧪 Version 2.5.0 (2025-12-15)

### Fitur Utama
- **Initial Prototype Release**: Rilis fondasi awal berbasis CLI & bridge komunikasi ADB raw socket untuk riset forensic internal.

---

| Versi | Tanggal Rilis | Status | Kategori |
| :--- | :--- | :--- | :--- |
| **v3.8.2** | 05 September 2026 | **Current Release** | Production Freeware |
| **v3.8.0** | 13 Agustus 2026 | Superseded | Public Freeware |
| **v3.7.0** | 20 Juli 2026 | Superseded | Feature Update |
| **v3.6.0** | 10 Juni 2026 | Superseded | Feature Update |
| **v3.5.0** | 02 Mei 2026 | Superseded | Major Rebrand |
| **v3.0.0** | 15 Januari 2026 | Archived | Stable Initial GUI |
| **v2.5.0** | 15 Desember 2025 | Archived | Alpha Prototype |

---
**Created by gbluez 2026**
