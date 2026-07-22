<div align="center">

```
 ████████╗       ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
 ╚══██╔══╝      ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║   █████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║   ╚════╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║         ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
```

**Next-Generation Security Operations Center — v2.2**

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04%2B-orange?style=flat-square&logo=ubuntu)](https://ubuntu.com)
[![Go](https://img.shields.io/badge/Built%20with-Go-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/Requires-Docker-2496ED?style=flat-square&logo=docker)](https://docker.com)

*One-binary deployment of a full open-source SOC stack.*

</div>

---

## 📖 Overview

**T-Guard** adalah platform SOC (*Security Operations Center*) open-source yang terintegrasi penuh, dapat diinstal hanya dengan satu perintah. T-Guard menggabungkan komponen-komponen terbaik dari ekosistem keamanan open-source ke dalam satu installer interaktif berbasis TUI.

### Stack yang Diinstal

| Komponen | Fungsi | Port |
|----------|--------|------|
| 🛡️ **Wazuh** | SIEM & XDR — deteksi ancaman, log analysis, FIM | `443`, `9200`, `55000` |
| ⚡ **n8n** | SOAR — otomasi respon insiden & integrasi workflow | `5678` |
| 🔄 **Shuffle** *(opsional)* | SOAR alternatif enterprise | `3001` |
| 🔍 **IRIS** | DFIR — platform manajemen insiden & investigasi | `8443` |
| 🌐 **MISP** | Threat Intelligence — berbagi & analisis IOC | `8080` |

---

## ✨ Fitur Utama

- **🖥️ TUI Interaktif** — Antarmuka terminal modern berbasis `bubbletea` + `huh`
- **🧠 Smart Hardware Detection** — Otomatis mendeteksi spesifikasi server (High-End / Standard / Entry-Level)
- **🌐 Auto IP Detection** — Mendukung Public Cloud dan Private Network/On-Premise
- **🔐 Certificate Auto-Generation** — Sertifikat SSL Wazuh Indexer dibuat otomatis
- **⚡ Idempotent Steps** — Aman dijalankan ulang; langkah yang sudah selesai dilewati
- **💀 PoC Mode** — Simulasi skenario serangan untuk uji deteksi Wazuh
- **🗑️ Clean Uninstall** — Hapus semua komponen hingga bersih

---

## 🚀 Quick Start

> **Prasyarat:** Ubuntu 22.04+ / Debian 11+, koneksi internet, `sudo` privileges.

### ⚡ Metode 1: One-Step via install.sh (Direkomendasikan)

```bash
git clone https://github.com/YOUR_ORG/t-guard.git
cd t-guard
sudo bash install.sh
```

Script `install.sh` akan otomatis:
- ✅ Memeriksa OS & spesifikasi hardware
- ✅ Menginstal Go & make via `apt` jika belum ada
- ✅ Build binary installer via `make build` jika binary belum ada
- ✅ Meluncurkan TUI installer T-Guard

### 🛠️ Metode 2: Gunakan Binary Pre-built

Jika binary `tguard-installer-cli` sudah tersedia dan Go sudah terinstal:

```bash
git clone https://github.com/YOUR_ORG/t-guard.git
cd t-guard
sudo ./tguard-installer-cli
```

### 🔨 Metode 3: Build Manual dari Source

```bash
git clone https://github.com/YOUR_ORG/t-guard.git
cd t-guard/tguard-installer

go mod download
go build -o ../tguard-installer-cli .

cd ..
sudo ./tguard-installer-cli
```

> Membutuhkan [Go 1.21+](https://golang.org/dl/).

### 🗑️ Uninstall

```bash
sudo bash uninstall.sh
```

---

## 🗺️ Mode Installer

Saat dijalankan, Anda akan memilih salah satu dari 4 mode:

### 1. 🔧 Full Installation
Instalasi dan integrasi penuh semua komponen secara otomatis:
- Deteksi hardware & konfigurasi Smart Mode
- Generate sertifikat SSL Wazuh
- Deploy Wazuh SIEM, SOAR (n8n/Shuffle), IRIS, MISP
- Injeksi API Key VirusTotal (opsional)
- Tampilkan ringkasan URL & kredensial semua service

### 2. 🔗 Integrate Manual
Untuk instalasi yang sudah ada — input URL dan API key tiap service satu per satu:
- Wazuh API URL + credentials
- IRIS URL + API Key
- MISP URL + API Key
- n8n URL
- Konfigurasi disimpan ke `/var/lib/tguard_state/integration.json`

### 3. 💀 PoC (Proof of Concept)
Jalankan simulasi serangan yang aman untuk menguji deteksi Wazuh:

| Skenario | Deskripsi |
|----------|-----------|
| **SSH Brute Force** | Simulasi login gagal berulang via SSH (tanpa password nyata) |
| **EICAR Malware** | Buat file EICAR test di direktori yang dipantau Wazuh FIM |
| **Web Defacement** | Ganti konten halaman web dengan halaman deface simulasi |

### 4. 🗑️ Uninstall
Hapus semua komponen T-Guard hingga bersih:
- `docker compose down -v` semua service
- Hapus sertifikat Wazuh yang digenerate
- Hapus state file installer

---

## 📁 Struktur Proyek

```
t-guard/
├── tguard-installer-cli       # ⚡ Binary pre-built (langsung jalankan)
│
├── tguard-installer/          # Source code installer CLI (Go)
│   ├── main.go                # Entry point + TUI form logic
│   ├── go.mod
│   └── pkg/
│       ├── docker/            # Docker daemon & compose utilities
│       ├── env/               # Path resolution
│       ├── hardware/          # Hardware analysis & tier detection
│       ├── network/           # IP detection (public/private)
│       ├── orchestration/     # Deployment orchestration
│       │   ├── orchestration.go   # Core step runner & helpers
│       │   ├── full_install.go    # Full installation flow
│       │   ├── integrate.go       # Manual integration config
│       │   ├── poc.go             # PoC scenario runner
│       │   ├── uninstall.go       # Clean uninstall
│       │   └── n8n.go             # n8n workflow injection
│       ├── state/             # Idempotency state tracking
│       └── system/            # OS checks, sudo utilities
│
├── wazuh-docker/              # Wazuh SIEM (single-node & multi-node)
│   └── single-node/
│       ├── docker-compose.yml
│       ├── generate-indexer-certs.yml
│       ├── config/            # Wazuh manager, indexer, dashboard config
│       └── custom-integrations/  # VT, Shuffle, IRIS integrations
│
├── n8n/                       # n8n SOAR
│   ├── docker-compose.yml
│   └── templates/             # Pre-built T-Guard workflow JSON
│
├── shuffle/                   # Shuffle SOAR (alternatif)
│   └── templates/             # Pre-built T-Guard workflow JSON
│
├── iris-web/                  # IRIS DFIR Platform
│   └── docker-compose.yml
│
├── misp-docker/               # MISP Threat Intelligence
│   └── docker-compose.yml
│
├── scripts/                   # Utility scripts
│   ├── tguard_poc.py          # PoC scenario runner
│   ├── tguard_selfheal.py     # Self-healing & health checks
│   ├── tguard_env_doctor.py   # Pre-flight environment checker
│   └── tguard_account_doctor.py  # Service account validator
│
└── usecase/                   # PoC assets
    └── webdeface/             # Web defacement simulation files
```

---

## 📊 Persyaratan Hardware (Requirements)

| Spesifikasi | vCPU | RAM | Storage | Cocok untuk |
|------|-----|-----|------|-------------|
| ⚠️ **Entry-Level** | 4 Cores | 8 GB | 50 GB SSD | Basic testing (PoC), Lab, 1-2 endpoint agents, trafik sangat rendah. |
| ⚡ **Standard** | 8 Cores | 16 GB | 100 GB SSD | Production (Small/Medium Business), traffic moderat, 10-50 agents. |
| ✦ **High-End** | 16+ Cores | 32+ GB | 500+ GB SSD | Enterprise Production, high volume logging, MISP intensif, 100+ agents. |

> ℹ️ Installer akan otomatis mendeteksi spesifikasi server Anda saat proses instalasi berjalan.

---

## 🔐 Kredensial Default

> **⚠️ WAJIB diganti setelah instalasi pertama!**

| Service | URL | Username | Password |
|---------|-----|----------|----------|
| Wazuh Dashboard | `https://IP:443` | `admin` | `SecretPassword` |
| Wazuh API | `https://IP:55000` | `wazuh-wui` | `MyS3cr37P450r.*-` |
| IRIS | `https://IP:8443` | `administrator` | `MySuperAdminPassword!` |
| MISP | `https://IP:8080` | `admin@admin.test` | `admin` |
| n8n | `http://IP:5678` | *(buat saat pertama login)* | — |

> ⚠️ **Catatan Integrasi Sistem:** Sistem SOC akan menyala otomatis, **namun** API Key untuk MISP dan IRIS dibuat secara dinamis setelah Anda *login*. Ambil API Key dari dalam MISP & IRIS Anda, lalu jalankan menu `[2] Integrate Manual` pada Installer T-Guard untuk menyuntikkan kuncinya ke dalam Wazuh!

---

## 🏗️ Build dari Source

```bash
# Prasyarat: Go 1.21+
cd tguard-installer
go mod download
go build -o ../tguard-installer-cli .

# Jalankan dari root direktori
cd ..
sudo ./tguard-installer-cli
```

---

## 🔒 Catatan Keamanan

1. **Ganti semua password default** segera setelah instalasi
2. **Aktifkan firewall** dan batasi akses hanya dari IP yang dipercaya:
   ```bash
   sudo ufw enable
   sudo ufw allow from <your-ip> to any port 443,5678,8443,8080,9200,55000
   ```
3. File `.env` yang berisi secrets **tidak boleh di-commit** ke Git (sudah dikecualikan di `.gitignore`)
4. Sertifikat SSL yang digenerate menggunakan self-signed certificate — pertimbangkan Let's Encrypt untuk production

---

## 🤝 Kontribusi

Pull request sangat disambut! Silakan buka issue terlebih dahulu untuk mendiskusikan perubahan besar.

1. Fork repository
2. Buat branch: `git checkout -b feature/nama-fitur`
3. Commit: `git commit -m 'feat: tambah fitur xyz'`
4. Push: `git push origin feature/nama-fitur`
5. Buka Pull Request

---

## 📄 Lisensi

Proyek ini dilisensikan di bawah [MIT License](LICENSE).

Komponen third-party memiliki lisensi masing-masing:
- Wazuh — GPL v2
- MISP — AGPL v3
- IRIS — LGPL v3
- n8n — Sustainable Use License

---

