package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// AuthHandler menangani semua alur autentikasi OIDC.
type AuthHandler struct {
	OAuth2Config *oauth2.Config
	Verifier     *gooidc.IDTokenVerifier
	Store        sessions.Store
	Tmpl         *template.Template
	IssuerURL    string
}

// Claims merepresentasikan payload dari JWT token Keycloak.
// Ini adalah field-field yang kita parse dari ID Token dan Access Token.
type Claims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`

	// Keycloak meletakkan realm roles di dalam struktur ini
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// HasRole mengecek apakah user memiliki role tertentu.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.RealmAccess.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Login memulai alur Authorization Code Flow.
//
// Alur yang terjadi:
// 1. Generate "state" token — string random untuk mencegah CSRF attack.
//    CSRF (Cross-Site Request Forgery) terjadi ketika attacker menipu browser
//    user untuk mengirim request yang tidak diinginkan. State token memastikan
//    callback yang diterima berasal dari request login yang kita inisiasi.
//
// 2. Generate "code verifier" untuk PKCE (Proof Key for Code Exchange).
//    PKCE adalah layer keamanan tambahan. Prosesnya:
//    - Kita buat string random (code_verifier)
//    - Kita hash code_verifier tersebut (code_challenge)
//    - code_challenge dikirim ke Keycloak saat request login
//    - Saat tukar token, kita kirim code_verifier asli
//    - Keycloak verifikasi bahwa hash(code_verifier) == code_challenge
//    Ini mencegah token interception attack.
//
// 3. Redirect user ke halaman login Keycloak.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	session, err := h.Store.Get(r, "auth-session")
	if err != nil {
		// Buat session baru jika error
		session, _ = h.Store.New(r, "auth-session")
	}

	// Generate state untuk CSRF protection
	state, err := generateRandomString(32)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate PKCE code verifier dan challenge
	codeVerifier, err := generateRandomString(64)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Simpan state dan code_verifier di session (sisi server)
	// untuk diverifikasi nanti di callback
	session.Values["state"] = state
	session.Values["code_verifier"] = codeVerifier
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Buat URL redirect ke Keycloak dengan semua parameter yang diperlukan
	authURL := h.OAuth2Config.AuthCodeURL(
		state,
		// PKCE: kirim code_challenge (hash dari code_verifier)
		oauth2.S256ChallengeOption(codeVerifier),
		// Minta Keycloak untuk selalu tampilkan halaman login
		// (bisa diubah ke "none" jika mau SSO silent)
		oauth2.SetAuthURLParam("prompt", "login"),
	)

	log.Printf("Redirecting user to Keycloak: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback menangani response dari Keycloak setelah user login.
//
// Alur yang terjadi:
// 1. Verifikasi state untuk mencegah CSRF
// 2. Tukar authorization code dengan tokens menggunakan code_verifier (PKCE)
// 3. Verifikasi dan parse ID Token
// 4. Simpan informasi user di session
// 5. Redirect ke dashboard
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	session, err := h.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// ─── Verifikasi State (CSRF Protection) ───
	expectedState, ok := session.Values["state"].(string)
	if !ok || expectedState == "" {
		http.Error(w, "State tidak valid (session mungkin expired)", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != expectedState {
		http.Error(w, "State mismatch — kemungkinan CSRF attack", http.StatusBadRequest)
		return
	}

	// Cek apakah Keycloak mengembalikan error
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.Printf("Keycloak error: %s - %s", errParam, errDesc)
		http.Error(w, "Login gagal: "+errDesc, http.StatusUnauthorized)
		return
	}

	// Ambil authorization code dari query parameter
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code tidak ditemukan", http.StatusBadRequest)
		return
	}

	// Ambil code_verifier dari session (untuk PKCE)
	codeVerifier, ok := session.Values["code_verifier"].(string)
	if !ok || codeVerifier == "" {
		http.Error(w, "Code verifier tidak ditemukan di session", http.StatusBadRequest)
		return
	}

	// ─── Tukar Code dengan Token ───
	// Ini adalah request HTTP POST ke token_endpoint Keycloak.
	// Di balik layar, oauth2 library mengirim:
	// - grant_type: authorization_code
	// - code: authorization code dari Keycloak
	// - redirect_uri: harus sama dengan yang didaftarkan
	// - code_verifier: untuk verifikasi PKCE
	// - client_id & client_secret: identitas aplikasi kita
	ctx := context.Background()
	oauth2Token, err := h.OAuth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(codeVerifier), // PKCE verification
	)
	if err != nil {
		log.Printf("Gagal menukar code dengan token: %v", err)
		http.Error(w, "Gagal mendapatkan token dari Keycloak", http.StatusInternalServerError)
		return
	}

	// ─── Verifikasi dan Parse ID Token ───
	// ID Token adalah JWT yang berisi informasi identitas user.
	// Kita WAJIB memverifikasi signature-nya untuk memastikan
	// token ini benar-benar dari Keycloak, bukan token palsu.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "ID Token tidak ditemukan dalam response", http.StatusInternalServerError)
		return
	}

	idToken, err := h.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("ID Token verification gagal: %v", err)
		http.Error(w, "Token tidak valid", http.StatusUnauthorized)
		return
	}

	// Parse claims dari ID Token
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("Gagal parse claims: %v", err)
		http.Error(w, "Gagal memproses informasi user", http.StatusInternalServerError)
		return
	}

	// Juga parse Access Token untuk mendapatkan realm roles
	// (Keycloak meletakkan roles di Access Token, bukan ID Token by default)
	if err := parseAccessTokenClaims(oauth2Token.AccessToken, &claims); err != nil {
		log.Printf("Warning: gagal parse access token claims: %v", err)
	}

	log.Printf("User berhasil login: %s (%s)", claims.PreferredUsername, claims.Email)

	// ─── Simpan Data ke Session ───
	session.Values["authenticated"] = true
	session.Values["user_id"] = claims.Subject
	session.Values["username"] = claims.PreferredUsername
	session.Values["email"] = claims.Email
	session.Values["name"] = claims.Name
	session.Values["given_name"] = claims.GivenName
	session.Values["roles"] = claims.RealmAccess.Roles
	session.Values["access_token"] = oauth2Token.AccessToken
	session.Values["refresh_token"] = oauth2Token.RefreshToken
	session.Values["id_token"] = rawIDToken // Save id_token for logout hint
	session.Values["token_expiry"] = oauth2Token.Expiry.Unix()

	// Bersihkan state dan code_verifier — tidak diperlukan lagi
	delete(session.Values, "state")
	delete(session.Values, "code_verifier")

	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session setelah login: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// Logout mengakhiri session dan me-redirect user ke Keycloak untuk logout global.
//
// Keycloak mendukung "single logout" — ketika user logout dari satu aplikasi,
// session di Keycloak juga dihapus sehingga SSO (Single Sign-On) ke aplikasi
// lain juga ikut ter-logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var idToken string
	session, err := h.Store.Get(r, "auth-session")
	if err == nil {
		idToken, _ = session.Values["id_token"].(string)

		// Hapus semua data session
		for key := range session.Values {
			delete(session.Values, key)
		}
		session.Options.MaxAge = -1 // Hapus cookie
		session.Save(r, w)
	}

	// Redirect ke endpoint logout Keycloak untuk single logout
	// post_logout_redirect_uri adalah halaman yang dituju setelah logout selesai
	keycloakLogoutURL := h.IssuerURL + "/protocol/openid-connect/logout" +
		"?post_logout_redirect_uri=http://localhost:9090" +
		"&client_id=" + h.OAuth2Config.ClientID

	if idToken != "" {
		keycloakLogoutURL += "&id_token_hint=" + idToken
	}

	log.Println("User logout, redirect ke Keycloak logout endpoint")
	http.Redirect(w, r, keycloakLogoutURL, http.StatusFound)
}

// ─────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────

// generateRandomString membuat string random yang aman secara kriptografis.
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// parseAccessTokenClaims mem-parse claims dari Access Token secara manual.
// Access Token adalah JWT, tapi kita tidak perlu memverifikasi signaturenya
// di sini karena kita baru saja mendapatkannya langsung dari Keycloak.
// Ini hanya untuk membaca realm roles yang disimpan Keycloak di Access Token.
func parseAccessTokenClaims(accessToken string, claims *Claims) error {
	// JWT format: header.payload.signature
	// Kita hanya perlu bagian payload (index 1)
	parts := splitJWT(accessToken)
	if len(parts) != 3 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	var accessClaims Claims
	if err := json.Unmarshal(payload, &accessClaims); err != nil {
		return err
	}

	// Merge realm roles dari access token ke claims utama
	if len(accessClaims.RealmAccess.Roles) > 0 {
		claims.RealmAccess.Roles = accessClaims.RealmAccess.Roles
	}

	return nil
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// SessionUser adalah representasi user dari session, dipakai di handlers lain.
type SessionUser struct {
	UserID    string
	Username  string
	Email     string
	Name      string
	GivenName string
	Roles     []string
	TokenExpiry time.Time
}

// HasRole mengecek role user.
func (u *SessionUser) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}
