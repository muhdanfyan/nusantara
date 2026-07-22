# Contributing to T-Guard

Terima kasih telah tertarik berkontribusi pada T-Guard! 🎉

## 🔧 Setup Development

```bash
git clone https://github.com/your-org/t-guard.git
cd t-guard/tguard-installer
go mod download
go build -o ../tguard-installer-cli
```

## 📋 Pedoman Kontribusi

### Melaporkan Bug
- Gunakan GitHub Issues
- Sertakan: OS version, output error lengkap, langkah reproduksi
- Tag dengan label `bug`

### Mengusulkan Fitur
- Buka Issue terlebih dahulu dengan label `enhancement`
- Diskusikan sebelum membuka Pull Request besar

### Pull Request
1. Fork repository
2. Buat branch dari `main`: `git checkout -b feat/nama-fitur`
3. Pastikan `go build` dan `go vet ./...` tidak ada error
4. Tulis commit message yang jelas: `feat:`, `fix:`, `docs:`, `refactor:`
5. Buka Pull Request ke branch `main`

## 📁 Struktur Kode (Go)

```
tguard-installer/
├── main.go               # TUI forms & menu logic
└── pkg/
    ├── docker/           # Docker utilities
    ├── env/              # Path resolution
    ├── hardware/         # Hardware detection
    ├── network/          # IP detection
    ├── orchestration/    # Business logic deployment
    ├── state/            # Idempotency tracking
    └── system/           # OS & sudo utilities
```

## 💡 Tips

- Gunakan `runStep(key, title, fn)` untuk menambah langkah deployment baru
- State idempotency otomatis ditangani oleh `state.IsStepDone()` dan `state.MarkStepDone()`
- Semua warna & style menggunakan variabel dari `orchestration.go` (`cyan`, `green`, `red`, dll.)
