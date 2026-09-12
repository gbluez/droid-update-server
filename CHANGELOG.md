# ANTIPAS - Complete Version & Release History

Dokumentasi riwayat rilis, fungsi, dan evolusi fitur aplikasi ANTIPAS sejak awal pengembangan.

---

## 🚀 Version 3.8.5 (2026-09-12) - *Current Release*

### 🛑 Standby Policy Restriction & Censorship Alert Popup
- **Popup Protes Sensor & Restriksi Kebijakan**: Menampilkan jendela popup beraksen merah elegan bergaya HUD saat sistem mencapai status standby.
- **Ikon Facebook Disilang Merah**: Kotak membulat biru khas Facebook dilengkapi huruf 'f' putih dan silang diagonal ganda tebal warna merah menyala (glowing crimson prohibition cross) beserta cincin larangan.
- **Pemberitahuan Larangan & Pengalihan Distribusi**:
  > *"Informasi update dan perbaikan tidak bisa di lakukan di sini, karena aturan yang entah dan harus di langgar."*
- **Tautan Langsung GitHub Releases (Hotlink)**: Baris *"Halaman Github masih ada dan akan selalu ada. [ Klik di sini ]"* dengan status hover hand cursor (IDC_HAND), glow text, dan aktivasi langsung menuju repositori rilis resmi gbluez/droid-update-server.
- **Timer Hitung Mundur & Progress Bar 10 Detik**: Durasi auto-dismiss 10 detik dengan bar visual merah menyala di bagian bawah serta opsi tutup manual instan ([ X ], ESC, Space, Enter).

### ⚙️ Pembaruan Biner & Sinkronisasi Rilis
- **Bumping Versi Biner 3.8.5**: Sinkronisasi header internal, metadata resource Windows (RC), judul jendela dinamis [3.8.5] Antipas, dan feed auto-updater JSON.

---

## 🚀 Version 3.8.4 (2026-09-10) - *Current Release*

### 📱 Panduan Visual Koneksi ADB & Dialog Otentikasi RSA (Mockup SVG)
- **Prompt Interaktif Pasca-Startup**: Menampilkan link otomatis di HUD terminal: `>>> Cara koneksi perangkat Android, klik Di Sini Boss :0 <<<` tepat setelah pemeriksaan versi.
- **Pembersihan Log Otomatis**: Layar dibersihkan secara instan saat link panduan diklik agar fokus dan informatif.
- **Ilustrasi Mockup Smartphone Vektor SVG**: Render grafis vektor resolusi tinggi layar smartphone dengan dialog otentikasi RSA asli (*"Izinkan debugging USB?"*).
- **Penunjuk Poin Kritis**: Callout visual kotak centang `[✓] Selalu izinkan dari komputer ini` dan tombol `[ IZINKAN ]` untuk mencegah status `unauthorized`.
- **Tabel Navigasi 7x Tap Vendor**: Panduan langkah demi langkah mengaktifkan Opsi Pengembang untuk Xiaomi/HyperOS, Samsung One UI, OPPO ColorOS, Realme UI, Vivo/iQOO, Transsion Infinix/Tecno/itel, Huawei/Honor, dan Google Pixel.
- **Popup Khusus Pabrikan**: Edukasi peringatan 3 tahap hitung mundur 5 detik Xiaomi, konfirmasi akses data Samsung, switch koneksi OTG 10 menit OPPO/Realme, otorisasi Vivo, dan HiSuite HDB Huawei.
- **Aksi Cepat 1-Klik**: Tombol instan Scan, Connect, Install Driver WHQL, dan Clear di bawah panduan.

### 🛠️ Driver Engine WHQL Multi-Vendor Universal (Enriched)
- **Dukungan Huawei & HiSilicon Kirin**: Kirin 9000/990/985/980/970/820/810/710/659, Huawei USB COM 1.0 (Testpoint Mode unbrick), HDB Bridge, CDC Modem.
- **Dukungan Transsion Holdings**: Infinix (GT/Zero/Note/Hot), Tecno (Phantom/Camon/Pova/Spark), itel (S/P/A), Preloader MTK, Unisoc Diag, Carlcare Service Port.
- **Dukungan OPPO Mobile (ColorOS)**: OPPO Preloader USB VCOM, Qualcomm MSM EDL 9008, CDC Diag Serial.
- **Dukungan Realme Mobile (Realme UI)**: Realme USB Driver, OPLUS BootROM handshake, Fastboot Composite.
- **Dukungan Vivo & iQOO (OriginOS / FuntouchOS)**: Vivo USB AT & Diag Port, Preloader VCOM, EDL 9008, Fastboot.
- **Platform Lainnya**: Qualcomm QDLoader 9008, MediaTek Dimensity/Helio, Samsung Exynos/Odin, Unisoc Tiger, Xiaomi HyperOS, Google Tensor.

### 🛡️ Proteksi Biner & Rilis Distribusi (Code Virtualizer)
- **Code Virtualizer Protection**: Proteksi biner rilis `dist/antipas.exe` dengan virtualisasi instruksi opcode dan enkripsi string anti-reverse engineering.
- **Paket Distribusi Bersih**: Pembuatan arsip terkompresi rilis `3.8.4.dist.7z` (LZMA2 Ultra) berisi biner terproteksi, DLL, engine malware, driver scripts, dan dokumentasi lengkap.

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
