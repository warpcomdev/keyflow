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
	GrantScope  []string `json:"grant_scope"`
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
func (hc *HydraClient) request(ctx context.Context, client *http.Client, path string, method string, challengeName, loginChallenge string, body interface{}, result interface{}) error {
	// Build query with params
	reqURL, err := url.Parse(hc.URL + path)
	if err != nil {
		return err
	}
	query := reqURL.Query()
	if loginChallenge != "" {
		query.Add(challengeName, loginChallenge)
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

// Reject a login Challenge, return redirect URL
func (hc *HydraClient) Reject(ctx context.Context, client *http.Client, loginChallenge string, reject ChallengeReject) (string, error) {
	var loginResp feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/login/reject", http.MethodPut, "login_challenge", loginChallenge, reject, &loginResp); err != nil {
		return "", err
	}
	return loginResp.RedirectTo, nil
}

// Accept a login Challenge, return redirect URL
func (hc *HydraClient) Accept(ctx context.Context, client *http.Client, loginChallenge string, accept LoginAccept) (string, error) {
	var feedback feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/login/accept", http.MethodPut, "login_challenge", loginChallenge, accept, &feedback); err != nil {
		return "", err
	}
	return feedback.RedirectTo, nil
}

// Challenge retrieves info from loginChallenge
func (hc *HydraClient) Challenge(ctx context.Context, client *http.Client, loginChallenge string) (zero Challenge, err error) {
	err = hc.request(ctx, client, "/oauth2/auth/requests/login", http.MethodGet, "login_challenge", loginChallenge, nil, &zero)
	return
}

// Reject a login Challenge, return redirect URL
func (hc *HydraClient) ConsentReject(ctx context.Context, client *http.Client, consentChallenge string, reject ChallengeReject) (string, error) {
	var feedback feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/consent/reject", http.MethodPut, "consent_challenge", consentChallenge, reject, &feedback); err != nil {
		return "", err
	}
	return feedback.RedirectTo, nil
}

// Accept a login Challenge, return redirect URL
func (hc *HydraClient) ConsentAccept(ctx context.Context, client *http.Client, consentChallenge string, accept ConsentAccept) (string, error) {
	var feedback feedbackResponse
	if err := hc.request(ctx, client, "/oauth2/auth/requests/consent/accept", http.MethodPut, "consent_challenge", consentChallenge, accept, &feedback); err != nil {
		return "", err
	}
	return feedback.RedirectTo, nil
}

// ConsentChallenge retrieves info from consentChallenge
func (hc *HydraClient) ConsentChallenge(ctx context.Context, client *http.Client, consentChallenge string) (zero Challenge, err error) {
	err = hc.request(ctx, client, "/oauth2/auth/requests/consent", http.MethodGet, "consent_challenge", consentChallenge, nil, &zero)
	return
}
