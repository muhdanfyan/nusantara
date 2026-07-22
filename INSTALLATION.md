# Panduan Instalasi T-Guard SOC v2.2

Selamat datang di panduan instalasi **T-Guard Security Operations Center (SOC)**.
T-Guard versi 2.2 kini menggunakan *Installer* berbasis Golang yang sangat cepat, kebal terhadap *crash*, dan cocok untuk skala *Enterprise*.

---

## 🚀 Langkah 1: Gerbang Utama (`install.sh`)

Satu-satunya skrip yang perlu Anda jalankan untuk memulai segalanya adalah `install.sh`. 
Skrip ini bertindak sebagai **Gerbang Utama** yang secara otomatis akan:
1. Mengecek sistem operasi Anda (Ubuntu/Debian).
2. Menginstal *requirements* dasar yang dibutuhkan sistem (seperti `golang`, `make`, `curl`, dan `apt-transport-https`).
3. Melakukan *compile* kode sumber Golang menjadi *binary* siap pakai (`tguard-installer-cli`).
4. Langsung mengeksekusi TUI (Terminal User Interface) Installer setelah proses kompilasi selesai.

### 💻 Cara Menjalankan:
Masuk ke folder repositori yang sudah Anda *clone*, lalu jalankan perintah ini sebagai `root` atau dengan `sudo`:

```bash
sudo bash install.sh
```

---

## ⚙️ Langkah 2: Mengikuti TUI Installer (Interaktif)

Setelah `install.sh` selesai menyiapkan lingkungan, antarmuka **TUI Installer** yang modern akan muncul di layar terminal Anda. Gunakan **Tombol Panah (Arrow Keys)** untuk navigasi dan **Enter** untuk memilih.

Proses instalasi sangat *straightforward*:

1. **Pilih Main Menu:** Pilih `[1] Full Installation`.
2. **Pilih SOAR Engine:** Pilih **n8n** (ringan & direkomendasikan) atau **Shuffle** (skala besar).
3. **Advanced Config:** 
   - Pilih **NO** untuk instalasi otomatis (Sangat Direkomendasikan).
   - Pilih **YES** hanya jika Anda pakar dan ingin mengubah alokasi memori atau port Docker secara manual.
4. **Integrasi VirusTotal:**
   - Jika pilih **YES**, siapkan API Key VirusTotal 64-karakter Anda untuk di-inject ke Wazuh.
   - Jika **NO**, lewati fitur intelijen ancaman ini.
5. **Konfirmasi Deploy:** Klik `Yes, start deployment!`.

---

## ☕ Langkah 3: Tunggu Proses Deployment

Installer Golang akan mengambil alih dan melakukan tugas berat secara otomatis:
- 🧠 Mendeteksi jumlah Core CPU, RAM, dan Storage Anda (*Hardware Profiling*).
- 🌐 Mendeteksi IP Lokal/Publik untuk *binding* jaringan yang benar.
- 🐳 Memeriksa *Docker Daemon* dan menginstalnya jika belum ada.
- 🚀 Melakukan pull *image* Docker berukuran besar (MISP, Wazuh, n8n, IRIS) dan menyalakannya menggunakan `docker compose up -d` dengan *timeout* dan *error handling* yang cerdas.

Setelah Anda melihat layar berwarna hijau yang bertuliskan **"✔ T-Guard Full Stack is up and running!"**, maka SOC Anda sudah hidup secara *container* dan *networking*.

---

## 🔗 Langkah 4: Menghubungkan API (Integrasi Sistem)

> **⚠️ PENTING (BACA INI):** 
> Meski sistem sudah berjalan (Otomatis), **API Keys** untuk MISP dan IRIS **BELUM terkonfigurasi secara otomatis** dengan Wazuh. Hal ini dikarenakan MISP dan IRIS meng-generate kunci tersebut secara unik untuk alasan keamanan setelah Anda *login* pertama kali.

**Cara mengaktifkan otomatisasi penuh (Auto-Integration):**
1. **Dapatkan MISP Key:** Buka `https://<IP_ANDA>:8080`, login (`admin@admin.test` / `admin`), pergi ke menu *Administration -> List Auth Keys* dan salin kuncinya.
2. **Dapatkan IRIS Key:** Buka `https://<IP_ANDA>:8443`, login (`administrator` / `MySuperAdminPassword!`), buka *Profile -> My Settings -> API Key* dan salin kuncinya.
3. Jalankan kembali installer T-Guard:
   ```bash
   sudo ./tguard-installer-cli
   ```
4. Pilih menu **[2] Integrate Manual**.
5. Masukkan URL dan *API Keys* yang sudah Anda dapatkan.
   Installer akan **otomatis menyuntikkan kunci tersebut ke dalam script Python Wazuh (`custom-misp.py` & `ossec.conf`)**. Tidak perlu konfigurasi manual!

---

## 🗑️ Cara Uninstall (Pembersihan)

**Anda tidak memerlukan skrip bash terpisah untuk melakukan uninstall.**
Karena Installer Golang (`tguard-installer-cli`) sudah merangkap tugas tersebut dengan sangat bersih.

Jika Anda ingin meratakan (*wipe-out*) semua sistem T-Guard, jalankan kembali *binary* installer:

```bash
sudo ./tguard-installer-cli
```
Lalu pilih menu **[5] Uninstall**. Installer akan secara otomatis:
- Menjalankan `docker compose down -v` pada semua komponen.
- Menghapus semua kontainer, *volume* (database), dan jaringan.
- Membuang instalasi Wazuh Agent lokal.
- Membersihkan jejak file *state* dan sertifikat SSL instalasi.

*Warning: Semua data Anda akan hilang secara permanen jika Anda menjalankan fitur ini!*
