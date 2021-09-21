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
	http.HandleFunc("/api/auth", api.Login)
	http.HandleFunc("/api/consent", api.Consent)
	http.ListenAndServe(":8080", nil)
}
