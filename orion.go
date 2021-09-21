package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Credentials required to log in
type Credentials struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Domain   string   `json:"domain"`
	Scopes   []string `json:"scopes,omitempty"`
}

// LoginInfo is the information returned on successful login
type LoginInfo struct {
	Subject  string   `json:"subject"`
	Username string   `json:"username"`
	Domain   string   `json:"domain"`
	Scopes   []string `json:"scopes,omitempty"`
}

// OrionClient encapsulates orion API
type OrionClient struct {
}

// Decode a subject into LoginInfo
func (o *OrionClient) Decode(subject string, scopes []string) (zero LoginInfo, err error) {
	creds := strings.SplitN(subject, "@", 2)
	if len(creds) != 2 {
		return zero, nil
	}
	loginInfo := LoginInfo{
		Subject:  subject,
		Username: creds[0],
		Domain:   creds[1],
		Scopes:   scopes,
	}
	return loginInfo, nil
}

// Skip auth, try to validate decoded info
func (o *OrionClient) Skip(ctx context.Context, client *http.Client, info LoginInfo) error {
	// TODO: Validate session
	return nil
}

// Login with the provided credentials
func (o *OrionClient) Login(ctx context.Context, client *http.Client, creds Credentials) (zero LoginInfo, err error) {
	if creds.Username == "" || creds.Password == "" || creds.Domain == "" {
		return zero, errors.New("Empty credentials")
	}
	// TODO: Authenticate session
	loginInfo := LoginInfo{
		Subject:  fmt.Sprintf("%s@%s", creds.Username, creds.Domain),
		Username: creds.Username,
		Domain:   creds.Domain,
		Scopes:   creds.Scopes,
	}
	return loginInfo, nil
}

// Consent with the provided scopes
func (o *OrionClient) Consent(ctx context.Context, client *http.Client, info LoginInfo) error {
	// TODO: Grant Consent for session
	return nil
}
