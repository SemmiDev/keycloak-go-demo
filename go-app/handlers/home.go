package handlers

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

// HomeHandler menangani halaman-halaman yang membutuhkan (atau tidak) autentikasi.
type HomeHandler struct {
	Store sessions.Store
	Tmpl  *template.Template
}

// Home adalah halaman landing publik.
func (h *HomeHandler) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	session, _ := h.Store.Get(r, "auth-session")
	isAuthenticated := session.Values["authenticated"] == true

	data := map[string]interface{}{
		"IsAuthenticated": isAuthenticated,
		"Username":        session.Values["username"],
	}

	if err := h.Tmpl.ExecuteTemplate(w, "home.html", data); err != nil {
		log.Printf("Error rendering home: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Dashboard adalah halaman protected — hanya bisa diakses user yang sudah login.
// Route ini sudah dilindungi oleh AuthMiddleware di main.go.
func (h *HomeHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := h.Store.Get(r, "auth-session")
	user := getUserFromSession(session)

	// Ambil expiry token untuk ditampilkan di UI (informatif)
	var tokenExpiryStr string
	if exp, ok := session.Values["token_expiry"].(int64); ok {
		expTime := time.Unix(exp, 0)
		if time.Now().Before(expTime) {
			remaining := time.Until(expTime).Round(time.Second)
			tokenExpiryStr = remaining.String()
		} else {
			tokenExpiryStr = "Expired"
		}
	}

	data := map[string]interface{}{
		"User":          user,
		"IsAdmin":       user.HasRole("admin"),
		"TokenExpiry":   tokenExpiryStr,
		"CurrentTime":   time.Now().Format("02 Jan 2006 15:04:05"),
	}

	if err := h.Tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("Error rendering dashboard: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Profile menampilkan detail profil user dari session (data berasal dari JWT claims).
func (h *HomeHandler) Profile(w http.ResponseWriter, r *http.Request) {
	session, _ := h.Store.Get(r, "auth-session")
	user := getUserFromSession(session)

	data := map[string]interface{}{
		"User":    user,
		"IsAdmin": user.HasRole("admin"),
	}

	if err := h.Tmpl.ExecuteTemplate(w, "profile.html", data); err != nil {
		log.Printf("Error rendering profile: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// getUserFromSession mengambil data user dari session dan mengubahnya
// menjadi struct SessionUser yang lebih mudah dipakai di template.
func getUserFromSession(session *sessions.Session) *SessionUser {
	user := &SessionUser{}

	if id, ok := session.Values["user_id"].(string); ok {
		user.UserID = id
	}
	if username, ok := session.Values["username"].(string); ok {
		user.Username = username
	}
	if email, ok := session.Values["email"].(string); ok {
		user.Email = email
	}
	if name, ok := session.Values["name"].(string); ok {
		user.Name = name
	}
	if givenName, ok := session.Values["given_name"].(string); ok {
		user.GivenName = givenName
	}
	if roles, ok := session.Values["roles"].([]string); ok {
		user.Roles = roles
	}

	return user
}
