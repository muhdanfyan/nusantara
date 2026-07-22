package hardware

import (
	"fmt"
	"math"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type ServerHardware struct {
	CPUCores      int
	CPUModel      string
	CPUSpeedMHz   float64
	TotalRAMGB    float64
	TotalSwapGB   float64
	FreeStorageGB float64
	Tier          string
}

// Analyze mensimulasikan fungsionalitas analyze_server_hardware dari script bash lama
func Analyze() (*ServerHardware, error) {
	hw := &ServerHardware{}

	// Ambil info CPU
	cpuCount, err := cpu.Counts(true)
	if err == nil {
		hw.CPUCores = cpuCount
	}

	cpuInfo, err := cpu.Info()
	if err == nil && len(cpuInfo) > 0 {
		hw.CPUModel = cpuInfo[0].ModelName
		hw.CPUSpeedMHz = cpuInfo[0].Mhz
	}

	// Ambil info RAM & Swap
	v, err := mem.VirtualMemory()
	if err == nil {
		hw.TotalRAMGB = float64(v.Total) / math.Pow(1024, 3)
		hw.TotalSwapGB = float64(v.SwapTotal) / math.Pow(1024, 3)
	}

	// Ambil info Disk (Root /)
	d, err := disk.Usage("/")
	if err == nil {
		hw.FreeStorageGB = float64(d.Free) / math.Pow(1024, 3)
	}

	// Kalkulasi Server Tier (Mirip dengan logika Bash lama)
	if hw.CPUCores >= 8 && hw.TotalRAMGB >= 15.0 {
		hw.Tier = "High-End"
	} else if hw.CPUCores >= 4 && hw.TotalRAMGB >= 7.0 {
		hw.Tier = "Standard"
	} else {
		hw.Tier = "Entry-Level"
	}

	return hw, nil
}

// PrintReport menampilkan hasil analisa dengan format warna CLI
func (hw *ServerHardware) PrintReport() {
	fmt.Printf("\n[AI] ANALYZING SERVER HARDWARE & CAPABILITIES...\n")
	fmt.Printf("[+] CPU Cores    : %d Cores\n", hw.CPUCores)
	fmt.Printf("[+] CPU Model    : %s\n", hw.CPUModel)
	fmt.Printf("[+] CPU Speed    : %.0f MHz\n", hw.CPUSpeedMHz)
	fmt.Printf("[+] Total RAM    : %.1f GB\n", hw.TotalRAMGB)
	fmt.Printf("[+] Total Swap   : %.1f GB\n", hw.TotalSwapGB)
	fmt.Printf("[+] Free Storage : %.1f GB\n", hw.FreeStorageGB)

	fmt.Printf("\n[AI] CALCULATING SERVER TIER...\n")
	if hw.Tier == "High-End" {
		fmt.Printf("✦  SERVER TIER   : High-End (Full Capacity Available)\n\n")
	} else if hw.Tier == "Standard" {
		fmt.Printf("⚡ SERVER TIER   : Standard (Balanced Performance)\n\n")
	} else {
		fmt.Printf("⚠️  SERVER TIER   : Entry-Level (Hardware Bottleneck Warning)\n\n")
	}
}
