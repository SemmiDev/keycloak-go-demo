package middleware

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// AuthMiddleware melindungi route yang membutuhkan autentikasi.
type AuthMiddleware struct {
	Store        sessions.Store
	OAuth2Config *oauth2.Config
}

// Require adalah middleware yang membungkus handler.
// Jika user belum authenticated, dia akan di-redirect ke /login.
//
// Cara kerja middleware pattern di Go:
// Middleware menerima http.Handler dan mengembalikan http.Handler baru
// yang "membungkus" handler asli dengan logika tambahan.
func (m *AuthMiddleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.Store.Get(r, "auth-session")
		if err != nil {
			log.Printf("Session error di middleware: %v", err)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Cek apakah user sudah authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			log.Printf("Akses ditolak ke %s — user belum login", r.URL.Path)
			// Simpan URL yang dituju agar bisa redirect setelah login
			// (fitur opsional, bisa ditambahkan sebagai improvement)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// ─── Refresh Token Logic ───
		accessToken, _ := session.Values["access_token"].(string)
		refreshToken, _ := session.Values["refresh_token"].(string)
		tokenExpiryInt, _ := session.Values["token_expiry"].(int64)

		if accessToken != "" && refreshToken != "" && m.OAuth2Config != nil {
			expiry := time.Unix(tokenExpiryInt, 0)

			// Build oauth2.Token from session
			oldToken := &oauth2.Token{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				Expiry:       expiry,
			}

			// TokenSource handles automatic refresh if the token is expired
			tokenSource := m.OAuth2Config.TokenSource(context.Background(), oldToken)
			newToken, err := tokenSource.Token()

			if err != nil {
				log.Printf("Gagal refresh token: %v", err)
				// Kalo refresh token gagal/expired, paksa login ulang
				session.Values["authenticated"] = false
				session.Save(r, w)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			// Cek apakah token benar-benar di-refresh (jika string AccessToken berbeda)
			if newToken.AccessToken != oldToken.AccessToken {
				log.Println("Token expired, berhasil melakukan refresh token secara otomatis!")
				session.Values["access_token"] = newToken.AccessToken
				session.Values["refresh_token"] = newToken.RefreshToken
				session.Values["token_expiry"] = newToken.Expiry.Unix()
				session.Save(r, w)
			}
		}

		// User sudah terautentikasi (dan token valid) — lanjutkan ke handler berikutnya
		next.ServeHTTP(w, r)
	})
}
