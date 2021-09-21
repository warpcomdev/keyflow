package main

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// JWT encapsulates methods to sign and check a token
type JWT struct {
	Issuer        string // Issuer to use in JWT tokens
	SigningMethod jwt.SigningMethod
	Keyfunc       jwt.Keyfunc
}

// Sign the claims provided
func (j *JWT) Sign(claims jwt.StandardClaims, audience string) (string, error) {
	claims.Issuer, claims.Audience = j.Issuer, audience
	jwtToken := jwt.NewWithClaims(j.SigningMethod, claims)
	key, err := j.Keyfunc(nil)
	if err != nil {
		return "", err
	}
	return jwtToken.SignedString(key)
}

// Extract claims from valid signed token
func (j *JWT) Check(token string) (zero jwt.StandardClaims, err error) {
	jwtToken, err := jwt.Parse(token, j.Keyfunc)
	if err != nil {
		return zero, err
	}
	if !jwtToken.Valid {
		return zero, fmt.Errorf("Token could not be validated")
	}
	if jwtToken.Method != j.SigningMethod {
		return zero, fmt.Errorf("Invalid signing method")
	}
	claims, ok := jwtToken.Claims.(jwt.StandardClaims)
	if !ok {
		return zero, fmt.Errorf("Failed to parse standard claims")
	}
	return claims, nil
}
