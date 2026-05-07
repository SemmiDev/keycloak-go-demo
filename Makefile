.PHONY: up down logs app clean help

# ─────────────────────────────────────────────────────────────────────────────
# Keycloak + Go App — Development Commands
# ─────────────────────────────────────────────────────────────────────────────

help: ## Tampilkan daftar command
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Docker / Keycloak ────────────────────────────────────────────────────────

up: ## Jalankan Keycloak + PostgreSQL
	@echo "🔄 Menjalankan Keycloak dan PostgreSQL..."
	docker compose up -d
	@echo "⏳ Menunggu Keycloak siap (bisa 60-90 detik pertama kali)..."
	@echo "   Pantau: make logs"
	@echo "   Keycloak Admin: http://localhost:8080 (admin/admin)"

down: ## Hentikan semua container
	docker compose down

logs: ## Lihat logs Keycloak
	docker compose logs -f keycloak

logs-all: ## Lihat semua logs
	docker compose logs -f

status: ## Cek status container
	docker compose ps

restart-kc: ## Restart hanya Keycloak (berguna saat iterasi config)
	docker compose restart keycloak

clean: ## Hapus container DAN volume (data hilang!)
	@echo "⚠️  Ini akan menghapus semua data Keycloak!"
	@read -p "Yakin? (y/N): " confirm && [ "$$confirm" = "y" ]
	docker compose down -v
	@echo "✓ Selesai"

# ── Go App ───────────────────────────────────────────────────────────────────

deps: ## Download Go dependencies
	cd go-app && go mod tidy && go mod download

run: ## Jalankan Go app (pastikan Keycloak sudah up)
	@echo "🚀 Menjalankan Go app di http://localhost:9090"
	cd go-app && go run main.go

build: ## Build binary Go app
	cd go-app && go build -o ../bin/app main.go
	@echo "✓ Binary tersedia di ./bin/app"

# ── Full stack ───────────────────────────────────────────────────────────────

dev: ## Jalankan Keycloak + Go app sekaligus (butuh 2 terminal)
	@echo "Langkah:"
	@echo "  Terminal 1: make up && make logs"
	@echo "  Terminal 2: make deps && make run"
	@echo ""
	@echo "Atau gunakan: make up (tunggu Keycloak siap) lalu make run"
