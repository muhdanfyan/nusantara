BIN_NAME   := tguard-installer-cli
BUILD_DIR  := ./tguard-installer
OUTPUT     := ./$(BIN_NAME)

.PHONY: build clean run help

## build: Compile the TUI installer binary
build:
	@echo "[*] Building T-Guard Installer CLI..."
	cd $(BUILD_DIR) && go build -buildvcs=false -o ../$(BIN_NAME)
	@echo "[✔] Binary ready: $(OUTPUT)"

## clean: Remove compiled binary
clean:
	@rm -f $(OUTPUT)
	@echo "[✔] Cleaned."

## run: Build and run the installer (requires sudo)
run: build
	sudo $(OUTPUT)

## help: Show available commands
help:
	@grep -E '^##' Makefile | sed 's/## //'
