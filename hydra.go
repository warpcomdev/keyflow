package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	LOGIN_CHALLENGE   = "login_challenge"
	CONSENT_CHALLENGE = "consent_challenge"
)

// HydraClient encapsulates the Hydra protocols
type HydraClient struct {
	URL string
}

// ClientInfo contains all the information gathered about the API client
type ClientInfo struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	PolicyURL  string `json:"policy_uri"`
	TermsURI   string `json:"tos_uri"`
	ClientURI  string `json:"client_uri"`
	LogoURI    string `json:"logo_uri"`
}

// Challenge is the information obtained from a login or consent challenge
type Challenge struct {
	RequestedScope               []string   `json:"requested_scope"`
	RequestedAccessTokenAudience string     `json:"requested_access_token_audience"`
	Skip                         bool       `json:"skip"`
	Subject                      string     `json:"subject"`
	RequestUrl                   string     `json:"request_url"`
	Client                       ClientInfo `json:"client"`
}

// LoginAccept is the information sent for accepting a challenge
type LoginAccept struct {
	Subject                string            `json:"subject"`
	Remember               bool              `json:"remember,omitempty"`
	RememberFor            int               `json:"remember_for,omitempty"`
	ACR                    string            `json:"acr,omitempty"`
	Context                map[string]string `json:"context,omitempty"`
	ForceSubjectIdentifier string            `json:"force_subject_identifier,omitempty"`
}

// ConsentAccept is the information sent for accepting a challenge
type ConsentAccept struct {
	Scopes      []string `json:"grant_scope"`
	Remember    bool     `json:"remember,omitempty"`
	RememberFor int      `json:"remember_for,omitempty"`
}

// ChallengeReject is the information sent for rejecting a challenge
type ChallengeReject struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorHint        string `json:"error_hint"`
	ErrorDebug       string `json:"error_debug"`
	StatusCode       int    `json:"status_code"`
}

// feedbackResponse is the information returned by hydra for auth and consent accepts or rejects
type feedbackResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// JsonError is the kind of error returned by hydra
type JsonError struct {
	StatusCode       int    `json:"status_code"`
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorDebug       string `json:"error_debug,omitempty"`
}

// Json turns a LoginReject into a JsonError
func (r ChallengeReject) Json(statusCode int) JsonError {
	return JsonError{
		StatusCode:       statusCode,
		ErrorCode:        r.ErrorCode,
		ErrorDescription: r.ErrorDescription,
		ErrorDebug:       r.ErrorDebug,
	}
}

// exhaust a ReadCloser
func exhaust(body io.ReadCloser) {
	if body != nil {
		io.Copy(ioutil.Discard, body)
		body.Close()
	}
}

// Error implements error
func (err JsonError) Error() string {
	return fmt.Sprintf("[%s] %s", err.ErrorCode, err.ErrorDescription)
}

// Req builds a request with the given challenge, method and body
func (hc *HydraClient) request(ctx context.Context, client *http.Client, path string, method string, challengeName, challenge string, body interface{}, result interface{}) error {
	// Build query with params
	reqURL, err := url.Parse(hc.URL + path)
	if err != nil {
		return err
	}
	query := reqURL.Query()
	if challenge != "" {
		query.Add(challengeName, challenge)
	}
	// If body is not nil, create a ReadCloser
	var ioBody io.ReadCloser
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		ioBody = io.NopCloser(bytes.NewBuffer(buf))
	}
	// Run the request
	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), ioBody)
	if err != nil {
		return err
	}
	if ioBody != nil {
		req.Header.Add("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if resp != nil {
		// Always exhaust body
		defer exhaust(resp.Body)
	}
	if err != nil {
		return err
	}
	unmarshal := json.NewDecoder(resp.Body)
	if resp.StatusCode != 200 {
		var jsonError JsonError
		if err = unmarshal.Decode(&jsonError); err != nil {
			return err
		}
		return jsonError
	}
	if err = unmarshal.Decode(result); err != nil {
		return err
	}
	return nil
}

// AuthReject a login Challenge, return redirect URL
func (hc *HydraClient) AuthReject(ctx context.Context, client *http.Client, challenge string, reject ChallengeReject) (string, error) {
	var loginResp feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/login/reject", http.MethodPut, LOGIN_CHALLENGE, challenge, reject, &loginResp); err != nil {
		return "", err
	}
	return loginResp.RedirectTo, nil
}

// AuthAccept a login Challenge, return redirect URL
func (hc *HydraClient) AuthAccept(ctx context.Context, client *http.Client, challenge string, accept LoginAccept) (string, error) {
	var feedback feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/login/accept", http.MethodPut, LOGIN_CHALLENGE, challenge, accept, &feedback); err != nil {
		return "", err
	}
	return feedback.RedirectTo, nil
}

// AuthChallenge retrieves info from loginChallenge
func (hc *HydraClient) AuthChallenge(ctx context.Context, client *http.Client, challenge string) (zero Challenge, err error) {
	err = hc.request(ctx, client, "/oauth2/auth/requests/login", http.MethodGet, LOGIN_CHALLENGE, challenge, nil, &zero)
	return
}

// ConsentReject a consent Challenge, return redirect URL
func (hc *HydraClient) ConsentReject(ctx context.Context, client *http.Client, challenge string, reject ChallengeReject) (string, error) {
	var feedback feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/consent/reject", http.MethodPut, CONSENT_CHALLENGE, challenge, reject, &feedback); err != nil {
		return "", err
	}
	return feedback.RedirectTo, nil
}

// ConsentAccept a consent Challenge, return redirect URL
func (hc *HydraClient) ConsentAccept(ctx context.Context, client *http.Client, challenge string, accept ConsentAccept) (string, error) {
	var feedback feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/consent/accept", http.MethodPut, CONSENT_CHALLENGE, challenge, accept, &feedback); err != nil {
		return "", err
	}
	return feedback.RedirectTo, nil
}

// ConsentChallenge retrieves info from consentChallenge
func (hc *HydraClient) ConsentChallenge(ctx context.Context, client *http.Client, challenge string) (zero Challenge, err error) {
	err = hc.request(ctx, client, "/oauth2/auth/requests/consent", http.MethodGet, CONSENT_CHALLENGE, challenge, nil, &zero)
	return
}
