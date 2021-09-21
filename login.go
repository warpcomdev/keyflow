package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	ErrorMissingChallenge       = "missing_challenge"
	ErrorChallengeRequestFail   = "challenge_request_fail"
	ErrorRejectRequestFail      = "reject_request_fail"
	ErrorAcceptRequestFail      = "accept_request_fail"
	ErrorTokenFailed            = "token_failed"
	ErrorUnsupportedContentType = "unsupported_content_type"
	ErrorInvalidContent         = "invalid_content"
	ErrorSigningFailed          = "signing_failed"
	ErrorAuthFailed             = "auth_failed"
	ErrorSkipFailed             = "skip_failed"

	CookieLoginChallenge   = "orionauth2-login-challenge"
	CookieConsentChallenge = "orionauth2-consent-challenge"
	CookieJwt              = "orionauth2-login-jwt"
)

// Api controls the login and grant flows
type Api struct {
	LoginPath      string        // Path to login page
	ErrorPath      string        // Path to error page
	ConsentPath    string        // Path to consent page
	CookieLifetime time.Duration // Session lifetime
	Client         *http.Client  // http Client
	HydraClient    *HydraClient  // Hydra API client
	JWT            *JWT          // JWT settings
	Orion          *OrionClient  // Orion client
}

// LoginRequest contains the information POSTed as json to the server
type LoginRequest struct {
	Credentials
	RememberFor int `json:"remember_for"`
	// If Retry == true, an authentication failure will not
	// trigger a reject to Hydra.
	Retry bool `json:"retry"`
}

// ConsentRequest contains the information POSTed as json to the server
type ConsentRequest struct {
	GrantedScopes []string `json:"granted_scopes"`
	RememberFor   int      `json:"remember_for"`
	// If Retry == true, an authentication failure will not
	// trigger a reject to Hydra.
	Retry bool `json:"retry"`
}

// ErrorMessage returned by the API on error
type ErrorMessage struct {
	Redirect string `json:"redirect"`
	Fatal    bool   `json:"fatal"` // True if error was fatal and cannot be retried
	JsonError
}

// SuccessMessage returned by the API on auccess
type SuccessMessage struct {
	// On POST, this is always the redirect URL.
	// On GET, this is always the login page, unless there was an open session.
	Redirect string `json:"redirect"`
	// On POST, this is always the logged user info.
	// On GET, this is always empty, unless there is an open session.
	LoginInfo
	// Client and Scope are always empty for POST.
	Client ClientInfo `json:"client,omitempty"`
}

// Login handler for GET and POST routes
func (api *Api) Login(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	marshal := api.encoder(w, r)
	now := time.Now()
	// Get the challenge
	// -----------------
	challenge, err := api.getChallenge(w, r, now, marshal, CookieLoginChallenge, "login_challenge")
	if err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorMissingChallenge, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	// Check if we have a valid JWT
	// ----------------------------
	var jwtToken string
	for _, cookie := range r.Cookies() {
		if cookie.Name == CookieJwt && cookie.Expires.After(now) {
			jwtToken = cookie.Value
		}
	}
	if jwtToken != "" {
		info, exp, err := api.ReadJWT(jwtToken)
		if err == nil && info.Subject != "" {
			api.send(w, r, marshal, api.accept(r.Context(), challenge, now, exp, info))
			return
		}
		// If token is invalid, go ahead but make sure to remove the session
		w = cookieRemoverWriter{cookieName: CookieJwt, ResponseWriter: w}
	}
	// Method == GET: collect challenge information from hydra.
	// -----------------------------------------------------------
	if r.Method == http.MethodGet {
		challengeData, err := api.HydraClient.Challenge(r.Context(), api.Client, challenge)
		if err != nil {
			errMsg := newErrorMessage(http.StatusFailedDependency, ErrorChallengeRequestFail, "", err)
			api.send(w, r, marshal, errMsg)
			return
		}
		if challengeData.Skip {
			// either succeed or fail without showing login screen
			api.send(w, r, marshal, api.skip(r.Context(), now, challenge, challengeData))
			return
		}
		// If not Skip, GET requests get redirected to login
		api.send(w, r, marshal, SuccessMessage{
			Client:   challengeData.Client,
			Redirect: api.LoginPath,
		})
		return
	}
	// Method == POST: Validate provided credentials.
	// POST is only used by the API, so from now on, we don't Reject
	// unless the API asks (by setting Retry = false)
	// -------------------------------------------------------------
	var loginRequest LoginRequest
	if err := api.decode(r, &loginRequest); err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorInvalidContent, "", err)
		api.send(w, r, marshal, errMsg)
	}
	info, err := api.Orion.Login(r.Context(), api.Client, loginRequest.Credentials)
	if err != nil {
		var errMsg message = newErrorMessage(http.StatusUnauthorized, ErrorAuthFailed, "", err)
		if !loginRequest.Retry {
			// Retry == false, Reject the login_challenge
			errMsg = api.reject(r.Context(), challenge, ChallengeReject{
				StatusCode:       http.StatusUnauthorized,
				ErrorCode:        ErrorAuthFailed,
				ErrorDescription: "Invalid credentials or too many authentication attempts",
				ErrorHint:        "Authentication failed",
				ErrorDebug:       err.Error(),
			})
		}
		api.send(w, r, marshal, errMsg)
		return
	}
	// Authentication succeeded. Set Cookies.
	// --------------------------------------
	exp := now.Add(api.CookieLifetime)
	if err := api.WriteJWT(w, r, now, exp, info); err != nil {
		errMsg := newErrorMessage(http.StatusFailedDependency, ErrorSigningFailed, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	rem := now
	if loginRequest.RememberFor > 0 {
		rem = now.Add(time.Duration(loginRequest.RememberFor) * time.Second)
	}
	api.send(w, r, marshal, api.accept(r.Context(), challenge, now, rem, info))
}

// Login handler for GET and POST routes
func (api *Api) Consent(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	marshal := api.encoder(w, r)
	now := time.Now()
	// Get the challenge
	// -----------------
	challenge, err := api.getChallenge(w, r, now, marshal, CookieConsentChallenge, "consent_challenge")
	if err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorMissingChallenge, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	// Method == GET: collect challenge information from hydra.
	// -----------------------------------------------------------
	if r.Method == http.MethodGet {
		challengeData, err := api.HydraClient.ConsentChallenge(r.Context(), api.Client, challenge)
		if err != nil {
			errMsg := newErrorMessage(http.StatusFailedDependency, ErrorChallengeRequestFail, "", err)
			api.send(w, r, marshal, errMsg)
			return
		}
		if challengeData.Skip {
			// either succeed or fail without showing login screen
			api.send(w, r, marshal, api.skipConsent(r.Context(), now, challenge, challengeData))
			return
		}
		// If not Skip, GET requests get redirected to login
		api.send(w, r, marshal, SuccessMessage{
			Client:   challengeData.Client,
			Redirect: api.ConsentPath,
		})
		return
	}
	// Method == POST: Validate provided consents.
	// POST is only used by the API, so from now on, we don't Reject
	// unless the API asks (by setting Retry = false)
	// -------------------------------------------------------------
	var consentRequest ConsentRequest
	if err := api.decode(r, &consentRequest); err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorInvalidContent, "", err)
		api.send(w, r, marshal, errMsg)
	}
	info, err := api.Orion.Consent(r.Context(), api.Client, consentRequest.GrantedScopes)
	if err != nil {
		var errMsg message = newErrorMessage(http.StatusUnauthorized, ErrorAuthFailed, "", err)
		if !consentRequest.Retry {
			// Retry == false, Reject the login_challenge
			errMsg = api.rejectConsent(r.Context(), challenge, ChallengeReject{
				StatusCode:       http.StatusUnauthorized,
				ErrorCode:        ErrorAuthFailed,
				ErrorDescription: "Invalid credentials or too many authentication attempts",
				ErrorHint:        "Consent failed",
				ErrorDebug:       err.Error(),
			})
		}
		api.send(w, r, marshal, errMsg)
		return
	}
	// Consent succeeded. Set Cookies.
	// -------------------------------
	exp := now
	if consentRequest.RememberFor > 0 {
		exp = now.Add(time.Duration(consentRequest.RememberFor) * time.Second)
	}
	api.send(w, r, marshal, api.consent(r.Context(), challenge, now, exp, info))
}

// Logout handler for GET routes
func (api *Api) Logout(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieJwt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now(),
		Value:    "",
	})
	http.Redirect(w, r, api.LoginPath, http.StatusSeeOther)
}

// getChallenge gets the challenge from URL or cookie
func (api *Api) getChallenge(w http.ResponseWriter, r *http.Request, now time.Time, marshal *json.Encoder, cookieName, paramName string) (string, error) {
	challenge := r.URL.Query().Get(paramName)
	if challenge == "" {
		for _, cookie := range r.Cookies() {
			if cookie.Name == cookieName && cookie.Expires.After(now) {
				challenge = cookie.Value
			}
		}
	}
	if challenge == "" {
		return "", errors.New("Missing challenge")
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  now.Add(api.CookieLifetime),
		Value:    challenge,
	})
	return challenge, nil
}

// encoder builds a json encoder, if API requested json response
func (api *Api) encoder(w http.ResponseWriter, r *http.Request) *json.Encoder {
	hasAccept, acceptJson := r.Header.Values("Accept"), false
	for _, accept := range hasAccept {
		if strings.HasPrefix(accept, "aplication/json") {
			acceptJson = true
		}
	}
	if len(hasAccept) <= 0 {
		acceptJson = true
	}
	if acceptJson {
		return json.NewEncoder(w)
	}
	return nil
}

// Decode body into object
func (api *Api) decode(r *http.Request, data interface{}) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return JsonError{
			StatusCode:       http.StatusBadRequest,
			ErrorCode:        ErrorUnsupportedContentType,
			ErrorDescription: "Unsupported content type",
		}
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(data); err != nil {
		return JsonError{
			StatusCode:       http.StatusBadRequest,
			ErrorCode:        ErrorInvalidContent,
			ErrorDescription: "Unsupported content value",
		}
	}
	return nil
}

// Skip grant
func (api *Api) skip(ctx context.Context, now time.Time, challenge string, challengeData Challenge) message {
	// Confirm with Orion that it is ok to Skip
	info, err := api.Orion.Decode(challengeData.Subject, challengeData.RequestedScope)
	if err != nil {
		return api.reject(ctx, challenge, ChallengeReject{
			StatusCode:       http.StatusUnauthorized,
			ErrorCode:        "credentials_required",
			ErrorDescription: "Challenge could not be decoded",
			ErrorHint:        "You need to login again",
			ErrorDebug:       err.Error(),
		})
	}
	if err := api.Orion.Skip(ctx, api.Client, info); err != nil {
		return api.reject(ctx, challenge, ChallengeReject{
			StatusCode:       http.StatusUnauthorized,
			ErrorCode:        "skip_failed",
			ErrorDescription: "Authentication skip rejected",
			ErrorHint:        "Failed to skip credential verification",
			ErrorDebug:       err.Error(),
		})
	}
	// Do not refresh JWT or expiration.
	// TODO: Check if it works, or we need to keep the expiration
	// date in a cookie.
	return api.accept(ctx, challenge, now, now, info)
}

// ReadJWT reads and decodes the subject from jwt token
func (api *Api) ReadJWT(jwtString string) (zero LoginInfo, exp time.Time, err error) {
	claims, err := api.JWT.Check(jwtString)
	if err != nil {
		// Don't err if the token is just expired
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return zero, exp, nil
			}
		}
	}
	var scopes []string
	if claims.Audience != "" {
		scopes = strings.Split(claims.Audience, ",")
	}
	info, err := api.Orion.Decode(claims.Subject, scopes)
	if err != nil {
		return zero, exp, err
	}
	return info, time.Unix(claims.ExpiresAt, 0), nil
}

// WriteJWT saves JWT as Cookie
func (api *Api) WriteJWT(w http.ResponseWriter, r *http.Request, now, exp time.Time, info LoginInfo) error {
	var audience string
	if info.Scopes != nil {
		audience = strings.Join(info.Scopes, ",")
	}
	claims := jwt.StandardClaims{
		// Issuer filled by api.JWT
		Audience:  audience,
		Subject:   info.Subject,
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-time.Minute).Unix(),
		ExpiresAt: exp.Unix(),
	}
	jwtToken, err := api.JWT.Sign(claims, audience)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieJwt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  exp,
		Value:    jwtToken,
	})
	return nil
}

// Message represents a message with an optional Redirect field
type message interface {
	// RedirectOrDefault returns redirect URL if no empty, otherwise default value
	redirectOrDefault(defaultPath string) string
	statusCode() int
}

// accept updates the Hydra server and writes the response
func (api *Api) accept(ctx context.Context, loginChallenge string, now, exp time.Time, info LoginInfo) message {
	accept := LoginAccept{
		Subject: info.Subject,
		Context: map[string]string{
			"username": info.Username,
			"domain":   info.Domain,
		},
	}
	if remaining := exp.Sub(now); remaining > 0 {
		accept.RememberFor = int(remaining / time.Second)
		accept.Remember = true
	}
	redirect, err := api.HydraClient.Accept(ctx, api.Client, loginChallenge, accept)
	if err != nil {
		return newErrorMessage(http.StatusInternalServerError, ErrorAcceptRequestFail, "", err)
	}
	return SuccessMessage{
		LoginInfo: info,
		Redirect:  redirect,
	}
}

// reject updates the Hydra server and writes the response
func (api *Api) reject(ctx context.Context, loginChallenge string, loginReject ChallengeReject) message {
	redirect, err := api.HydraClient.Reject(ctx, api.Client, loginChallenge, loginReject)
	if err != nil {
		return newErrorMessage(http.StatusFailedDependency, ErrorRejectRequestFail, "", err)
	}
	return ErrorMessage{
		JsonError: loginReject.Json(http.StatusUnauthorized),
		Fatal:     true,
		Redirect:  redirect,
	}
}

// newErrorMessage builds an ErrorMessage from the error
func newErrorMessage(statusCode int, defaultErrCode, redirect string, err error) ErrorMessage {
	var jsonError JsonError
	if ok := errors.As(err, &jsonError); !ok {
		jsonError.StatusCode = statusCode
		jsonError.ErrorCode = defaultErrCode
		jsonError.ErrorDescription = err.Error()
	}
	return ErrorMessage{
		JsonError: jsonError,
		Redirect:  redirect,
	}
}

// Send the message either as json or as a redirect.
func (api *Api) send(w http.ResponseWriter, r *http.Request, encoder *json.Encoder, e message) {
	// If using JSON API, return json object
	if encoder != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(e.statusCode())
		encoder.Encode(e)
		return
	}
	// Otherwise, redirect to error page using SeeOther, to turn POST into GET.
	http.Redirect(w, r, e.redirectOrDefault(api.ErrorPath), http.StatusSeeOther)
}

// redirectOrDefault implements message
func (s SuccessMessage) redirectOrDefault(defaultPath string) string {
	// Success MUST have a redirect
	return s.Redirect
}

// statusCode implements message
func (s SuccessMessage) statusCode() int {
	// Success MUST return statusOK
	return http.StatusOK
}

// redirectORDefault implements message
func (e ErrorMessage) redirectOrDefault(errorPath string) string {
	if e.Redirect != "" {
		return e.Redirect
	}
	return errorPath + "?errorCode=" + url.QueryEscape(e.ErrorCode) + "&error=" + url.QueryEscape(e.ErrorDescription)
}

// statusCode implements message
func (e ErrorMessage) statusCode() int {
	return e.StatusCode
}

type cookieRemoverWriter struct {
	cookieName string
	http.ResponseWriter
}

func (c cookieRemoverWriter) WriteHeader(code int) {
	defer c.ResponseWriter.WriteHeader(code)
	for _, cookie := range c.Header().Values("Cookie") {
		// TODO: What's the best way to check if the cookie exists?
		if strings.HasPrefix(cookie, c.cookieName) {
			// Cookie is already updated, let it be
			return
		}
	}
	// Remove the cookie before returning
	http.SetCookie(c.ResponseWriter, &http.Cookie{
		Name:     c.cookieName,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Value:    "",
	})
}
