package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func main() {

	api := Api{
		LoginPath:      "/login",
		ErrorPath:      "/error",
		CookieLifetime: 1 * time.Hour,
		Client:         http.DefaultClient,
		HydraClient: &HydraClient{
			URL: "http://localhost:8080",
		},
		JWT: &JWT{
			Issuer:        "testIssuer",
			SigningMethod: jwt.SigningMethodHS512,
			Keyfunc: func(*jwt.Token) (interface{}, error) {
				return []byte("12345678901234567890123456789012"), nil
			},
		},
		Orion: &OrionClient{},
	}
	http.HandleFunc("/api/auth", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			api.GetLogin(w, r)
		} else {
			api.PostLogin(w, r)
		}
	}))
	http.HandleFunc("/api/consent", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			api.GetConsent(w, r)
		} else {
			api.PostConsent(w, r)
		}
	}))
	http.ListenAndServe(":8080", nil)
}
