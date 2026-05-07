package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/semmidev/keycloak-demo/handlers"
	"github.com/semmidev/keycloak-demo/middleware"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// Config menyimpan semua konfigurasi OIDC/OAuth2.
// Di production, nilainya harus dari environment variable atau secrets manager.
type Config struct {
	KeycloakURL  string
	Realm        string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AppPort      string
}

func main() {
	cfg := Config{
		KeycloakURL:  getEnv("KEYCLOAK_URL", "http://localhost:8080"),
		Realm:        getEnv("KEYCLOAK_REALM", "demo-realm"),
		ClientID:     getEnv("CLIENT_ID", "go-demo-app"),
		ClientSecret: getEnv("CLIENT_SECRET", "my-super-secret-client-secret"),
		RedirectURL:  getEnv("REDIRECT_URL", "http://localhost:9090/callback"),
		AppPort:      getEnv("APP_PORT", "9090"),
	}

	// ─────────────────────────────────────────────────────
	// Step 1: Inisialisasi OIDC Provider
	//
	// go-oidc akan mengambil metadata dari endpoint discovery Keycloak:
	// {keycloak_url}/realms/{realm}/.well-known/openid-configuration
	//
	// Endpoint discovery ini mengembalikan JSON berisi semua URL penting:
	// - authorization_endpoint (untuk redirect user login)
	// - token_endpoint (untuk tukar code dengan token)
	// - jwks_uri (untuk verifikasi signature JWT)
	// - userinfo_endpoint (untuk ambil info user)
	// ─────────────────────────────────────────────────────
	issuerURL := cfg.KeycloakURL + "/realms/" + cfg.Realm

	ctx := context.Background()
	provider, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatalf("Gagal menghubungi Keycloak di %s: %v\n"+
			"Pastikan Keycloak sudah running dan realm '%s' sudah ada.",
			issuerURL, err, cfg.Realm)
	}
	log.Printf("Berhasil terhubung ke Keycloak provider: %s", issuerURL)

	// ─────────────────────────────────────────────────────
	// Step 2: Konfigurasi OAuth2
	//
	// oauth2.Config adalah "resep" untuk berkomunikasi dengan Keycloak.
	// Scopes menentukan informasi apa yang kita minta:
	// - openid: wajib untuk OIDC, meminta ID Token
	// - profile: nama, username, dll
	// - email: alamat email user
	// - roles: roles Keycloak (kita perlu ini untuk RBAC)
	// ─────────────────────────────────────────────────────
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(), // Ambil otomatis dari discovery
		Scopes: []string{
			gooidc.ScopeOpenID,
			"profile",
			"email",
			"roles",
		},
	}

	// ─────────────────────────────────────────────────────
	// Step 3: OIDC Token Verifier
	//
	// Verifier ini dipakai untuk memvalidasi ID Token yang diterima dari Keycloak.
	// Validasi meliputi: signature, issuer, expiry, audience.
	// ─────────────────────────────────────────────────────
	verifier := provider.Verifier(&gooidc.Config{
		ClientID: cfg.ClientID,
	})

	// ─────────────────────────────────────────────────────
	// Step 4: Session Store
	//
	// Kita menyimpan token di server-side session (cookie-based dengan enkripsi).
	// Ini lebih aman daripada menyimpan token di localStorage browser.
	// ─────────────────────────────────────────────────────
	sessionKey := []byte(getEnv("SESSION_KEY", "super-secret-session-key-32chars"))
	store := sessions.NewFilesystemStore("", sessionKey)
	store.MaxLength(0) // Remove length limit so large tokens can be saved
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,  // Cookie tidak bisa diakses via JavaScript
		Secure:   false, // Ganti ke true di production (HTTPS)
		SameSite: http.SameSiteLaxMode,
	}

	// ─────────────────────────────────────────────────────
	// Step 5: Load HTML Templates
	// ─────────────────────────────────────────────────────
	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Gagal load templates: %v", err)
	}

	// ─────────────────────────────────────────────────────
	// Step 6: Kumpulkan semua dependency ke dalam handler
	// ─────────────────────────────────────────────────────
	authHandler := &handlers.AuthHandler{
		OAuth2Config: oauth2Config,
		Verifier:     verifier,
		Store:        store,
		Tmpl:         tmpl,
		IssuerURL:    issuerURL,
	}

	homeHandler := &handlers.HomeHandler{
		Store: store,
		Tmpl:  tmpl,
	}

	authMiddleware := &middleware.AuthMiddleware{
		Store:        store,
		OAuth2Config: oauth2Config,
	}

	// ─────────────────────────────────────────────────────
	// Step 7: Setup Routes
	// ─────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public routes
	mux.HandleFunc("/", homeHandler.Home)
	mux.HandleFunc("/login", authHandler.Login)
	mux.HandleFunc("/callback", authHandler.Callback)
	mux.HandleFunc("/logout", authHandler.Logout)

	// Protected routes — dibungkus middleware untuk cek autentikasi
	mux.Handle("/dashboard", authMiddleware.Require(http.HandlerFunc(homeHandler.Dashboard)))
	mux.Handle("/profile", authMiddleware.Require(http.HandlerFunc(homeHandler.Profile)))

	log.Printf("Server berjalan di http://localhost:%s", cfg.AppPort)
	log.Fatal(http.ListenAndServe(":"+cfg.AppPort, mux))
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}
