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
	ErrorRejectConsentFail      = "reject_consent_fail"
	ErrorAcceptConsentFail      = "accept_consent_fail"
	ErrorAcceptSessionExpired   = "accept_session_expired"
	ErrorTokenFailed            = "token_failed"
	ErrorUnsupportedContentType = "unsupported_content_type"
	ErrorInvalidContent         = "invalid_content"
	ErrorSigningFailed          = "signing_failed"
	ErrorAuthFailed             = "auth_failed"
	ErrorSkipFailed             = "skip_failed"

	CookieLoginChallenge   = "orionauth2-login-challenge"
	CookieConsentChallenge = "orionauth2-consent-challenge"
	CookieJwt              = "orionauth2-login-jwt"

	CurrentFlowAuth    = "auth"
	CurrentFlowConsent = "consent"
)

// Api controls the login and grant flows
type Api struct {
	LoginPath      string        // Path to login page
	AcceptPath     string        // Path to accept page (when already logged in)
	ConsentPath    string        // Path to consent page (when already logged in)
	ErrorPath      string        // Path to error page
	CookieLifetime time.Duration // Session lifetime
	Client         *http.Client  // http Client
	HydraClient    *HydraClient  // Hydra API client
	Orion          *OrionClient  // Orion client
	JWT            *JWT          // JWT settings
}

// LoginRequest contains the information POSTed as json to the server
type LoginRequest struct {
	Credentials
	Accept      bool `json:"accept"` // Just accept the request if session is open
	RememberFor int  `json:"remember_for"`
	// If Retry == true, an authentication failure will not
	// trigger a reject to Hydra.
	Retry bool `json:"retry"`
}

// ConsentRequest contains the information POSTed as json to the server
type ConsentRequest struct {
	Accept      bool `json:"accept"` // Just accept the request if session is open
	RememberFor int  `json:"remember_for"`
	// If Retry == true, an authentication failure will not
	// trigger a reject to Hydra.
	Retry bool `json:"retry"`
}

// ErrorMessage returned by the API on error
type ErrorMessage struct {
	Redirect string `json:"redirect"`
	Final    bool   `json:"final"` // True if error was fatal and cannot be retried
	JsonError
}

// SuccessMessage returned by the API on success
type SuccessMessage struct {
	// On POST, this is always the redirect URL.
	// On GET, this is always the login/consent page.
	Redirect string `json:"redirect"`
	Final    bool   `json:"final"` // True if auth process completed
	// On CONSENT, this is always the challenge user info.
	// On AUTH, this is the logged user info, if there is a session. Otherwise, it is empty.
	// This can be used to check whether the user is logged in or not.
	LoginInfo
	// Client is only returned for GET calls, both auth and consent.
	Client ClientInfo `json:"client,omitempty"`
}

// GetLogin handler for GET Login route
func (api *Api) GetLogin(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	marshal := api.encoder(w, r)
	now := time.Now()
	// Get the challenge. This function can be called either during the
	// auth flow, or the consent flow (it session expired)
	// -----------------------------------------------------------------
	isAuthFlow, challenge, err := api.getAuthChallenge(w, r, now, marshal)
	if err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorMissingChallenge, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	// collect challenge information from hydra.
	// We can be performing a login in the consent flow,
	// if the session is closed.
	// -------------------------------------------------
	var challengeData Challenge
	if isAuthFlow {
		challengeData, err = api.HydraClient.AuthChallenge(r.Context(), api.Client, challenge)
	} else {
		challengeData, err = api.HydraClient.ConsentChallenge(r.Context(), api.Client, challenge)
	}
	if err != nil {
		errMsg := newErrorMessage(http.StatusFailedDependency, ErrorChallengeRequestFail, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	if isAuthFlow && challengeData.Skip {
		// either succeed or fail without showing login screen
		api.send(w, r, marshal, api.skipAuth(r.Context(), now, challenge, challengeData))
		return
	}
	// If not skipped, GET requests are redirected to either
	// login form or accept form, depending on whether we have
	// a valid session.
	// ---------------------------------------------
	info, _, err := api.ReadJWT(r, now)
	redirect := api.LoginPath
	if err == nil && info.Subject != "" {
		redirect = api.AcceptPath
	} else {
		// If token is invalid, go ahead but make sure to remove the session
		removeCookie(w, CookieJwt)
	}
	api.send(w, r, marshal, SuccessMessage{
		LoginInfo: info,
		Client:    challengeData.Client,
		Redirect:  redirect,
	})
}

// PostLogin handler for POST Login route
func (api *Api) PostLogin(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	marshal := api.encoder(w, r)
	now := time.Now()
	// Get validation request
	// ----------------------
	var loginRequest LoginRequest
	if err := api.decode(r, &loginRequest); err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorInvalidContent, "", err)
		api.send(w, r, marshal, errMsg)
	}
	// Get the challenge
	// -----------------
	isAuthFlow, challenge, err := api.getAuthChallenge(w, r, now, marshal)
	if err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorMissingChallenge, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	// If we are accepting, check for expired session
	// ----------------------------------------------
	info, _, err := api.ReadJWT(r, now)
	if loginRequest.Accept && info.Subject == "" {
		// Tried to accept but session expired, reject
		// with Redirect => LoginPath.
		removeCookie(w, CookieJwt)
		api.send(w, r, marshal, newErrorMessage(
			http.StatusUnauthorized,
			ErrorAcceptSessionExpired,
			api.LoginPath,
			errors.New("Session expired, please login again"),
		))
		return
	}
	// Otherwise, check credentials
	// ----------------------------
	info, err = api.Orion.Login(r.Context(), api.Client, loginRequest.Credentials)
	if err != nil {
		var errMsg message = newErrorMessage(http.StatusUnauthorized, ErrorAuthFailed, "", err)
		if !loginRequest.Retry {
			// Retry == false, Reject the login_challenge
			errMsg = api.rejectAuth(r.Context(), challenge, ChallengeReject{
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
	// Authentication succeeded. Set session cookie
	// --------------------------------------------
	exp := now.Add(api.CookieLifetime)
	if err := api.WriteJWT(w, r, now, exp, info); err != nil {
		errMsg := newErrorMessage(http.StatusFailedDependency, ErrorSigningFailed, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	// If not isAuthFlow, go back to consent flow
	// ------------------------------------------
	if !isAuthFlow {
		api.send(w, r, marshal, SuccessMessage{
			Redirect:  api.ConsentPath,
			LoginInfo: info,
		})
		return
	}
	// Else, accept.
	// -------------
	rem := now
	if loginRequest.RememberFor > 0 {
		rem = now.Add(time.Duration(loginRequest.RememberFor) * time.Second)
	}
	api.send(w, r, marshal, api.accept(r.Context(), challenge, now, rem, info))
}

// GetConsent handler for GET Consent flow
func (api *Api) GetConsent(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	marshal := api.encoder(w, r)
	now := time.Now()
	// Get the challenge
	// -----------------
	challenge, err := api.getConsentChallenge(w, r, now, marshal)
	if err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorMissingChallenge, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	// Collect challenge information from hydra.
	// -----------------------------------------
	challengeData, err := api.HydraClient.ConsentChallenge(r.Context(), api.Client, challenge)
	if err != nil {
		errMsg := newErrorMessage(http.StatusFailedDependency, ErrorChallengeRequestFail, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	if challengeData.Skip {
		// either succeed or fail without showing consent screen
		api.send(w, r, marshal, api.skipConsent(r.Context(), now, challenge, challengeData))
		return
	}
	info, err := api.Orion.Decode(challengeData.Subject, challengeData.RequestedScope)
	if err != nil {
		api.send(w, r, marshal, api.rejectAuth(r.Context(), challenge, ChallengeReject{
			StatusCode:       http.StatusUnauthorized,
			ErrorCode:        "consent_subject_required",
			ErrorDescription: "Consent Challenge could not be decoded",
			ErrorHint:        "You need to login again",
			ErrorDebug:       err.Error(),
		}))
	}
	// If not Skip, GET requests get redirected to consent
	api.send(w, r, marshal, SuccessMessage{
		LoginInfo: info,
		Client:    challengeData.Client,
		Redirect:  api.ConsentPath,
	})
}

// GetConsent handler for GET Consent flow
func (api *Api) PostConsent(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	marshal := api.encoder(w, r)
	now := time.Now()
	// Make sure we remove the login challenge, in case we
	// have to divert the user to the login form.
	removeCookie(w, CookieLoginChallenge)
	// To consent, we need a valid session.
	// If there is no JWT, login first.
	// ------------------------------------
	info, _, err := api.ReadJWT(r, now)
	if info.Subject == "" {
		removeCookie(w, CookieJwt)
		api.send(w, r, marshal, newErrorMessage(
			http.StatusUnauthorized,
			ErrorAcceptSessionExpired,
			api.LoginPath,
			errors.New("Session expired, please login again"),
		))
		return
	}
	// Get the challenge and consent request.
	// We don't trust the client for this, only the challenge.
	// -------------------------------------------------------
	challenge, err := api.getConsentChallenge(w, r, now, marshal)
	if err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorMissingChallenge, "", err)
		api.send(w, r, marshal, errMsg)
		return
	}
	var consentRequest ConsentRequest
	if err := api.decode(r, &consentRequest); err != nil {
		errMsg := newErrorMessage(http.StatusBadRequest, ErrorInvalidContent, "", err)
		api.send(w, r, marshal, errMsg)
	}
	// Consent to the requested params
	if err = api.Orion.Consent(r.Context(), api.Client, info); err != nil {
		var errMsg message = newErrorMessage(http.StatusUnauthorized, ErrorAuthFailed, "", err)
		if !consentRequest.Retry {
			// Retry == false, Reject the consent_challenge
			errMsg = api.rejectConsent(r.Context(), challenge, ChallengeReject{
				StatusCode:       http.StatusUnauthorized,
				ErrorCode:        ErrorAuthFailed,
				ErrorDescription: "Invalid scopes or too many consent attempts",
				ErrorHint:        "Consent failed",
				ErrorDebug:       err.Error(),
			})
		}
		api.send(w, r, marshal, errMsg)
		return
	}
	// Consent succeeded.
	// ------------------
	exp := now
	if consentRequest.RememberFor > 0 {
		exp = now.Add(time.Duration(consentRequest.RememberFor) * time.Second)
	}
	api.send(w, r, marshal, api.consent(r.Context(), challenge, now, exp, info))
}

// Logout handler for GET routes
func (api *Api) Logout(w http.ResponseWriter, r *http.Request) {
	defer exhaust(r.Body)
	removeCookie(w, CookieJwt)
	http.Redirect(w, r, api.LoginPath, http.StatusSeeOther)
}

// getAuthChallenge gets the auth challenge from URL or cookie
func (api *Api) getAuthChallenge(w http.ResponseWriter, r *http.Request, now time.Time, marshal *json.Encoder) (isAuthFlow bool, challenge string, err error) {
	challenge, err = api.getChallenge(w, r, now, marshal, CookieLoginChallenge, LOGIN_CHALLENGE)
	if err == nil {
		return true, challenge, nil
	}
	challenge, err = api.getChallenge(w, r, now, marshal, CookieConsentChallenge, CONSENT_CHALLENGE)
	if err == nil {
		return false, challenge, nil
	}
	return true, "", err
}

// getAuthChallenge gets the auth challenge from URL or cookie
func (api *Api) getConsentChallenge(w http.ResponseWriter, r *http.Request, now time.Time, marshal *json.Encoder) (challenge string, err error) {
	return api.getChallenge(w, r, now, marshal, CookieConsentChallenge, CONSENT_CHALLENGE)
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
	// Refresh cookie, even if it already existed
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

// SkipAuth tries to skip auth
func (api *Api) skipAuth(ctx context.Context, now time.Time, challenge string, challengeData Challenge) message {
	// Confirm with Orion that it is ok to Skip
	info, err := api.Orion.Decode(challengeData.Subject, challengeData.RequestedScope)
	if err != nil {
		return api.rejectAuth(ctx, challenge, ChallengeReject{
			StatusCode:       http.StatusUnauthorized,
			ErrorCode:        "credentials_required",
			ErrorDescription: "Challenge could not be decoded",
			ErrorHint:        "You need to login again",
			ErrorDebug:       err.Error(),
		})
	}
	if err := api.Orion.SkipAuth(ctx, api.Client, info); err != nil {
		return api.rejectAuth(ctx, challenge, ChallengeReject{
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

// SkipConsent tries to skip consent
func (api *Api) skipConsent(ctx context.Context, now time.Time, challenge string, challengeData Challenge) message {
	// Confirm with Orion that it is ok to Skip
	info, err := api.Orion.Decode(challengeData.Subject, challengeData.RequestedScope)
	if err != nil {
		return api.rejectConsent(ctx, challenge, ChallengeReject{
			StatusCode:       http.StatusUnauthorized,
			ErrorCode:        "credentials_required",
			ErrorDescription: "Consent Challenge could not be decoded",
			ErrorHint:        "You need to login again",
			ErrorDebug:       err.Error(),
		})
	}
	if err := api.Orion.SkipConsent(ctx, api.Client, info); err != nil {
		return api.rejectConsent(ctx, challenge, ChallengeReject{
			StatusCode:       http.StatusUnauthorized,
			ErrorCode:        "skip_consent_failed",
			ErrorDescription: "Consent skip rejected",
			ErrorHint:        "Failed to skip consent verification",
			ErrorDebug:       err.Error(),
		})
	}
	// Do not refresh JWT or expiration.
	// TODO: Check if it works, or we need to keep the expiration
	// date in a cookie.
	return api.accept(ctx, challenge, now, now, info)
}

// ReadJWT reads and decodes the subject from jwt token
func (api *Api) ReadJWT(r *http.Request, now time.Time) (zero LoginInfo, exp time.Time, err error) {
	var jwtString string
	for _, cookie := range r.Cookies() {
		if cookie.Name == CookieJwt && cookie.Expires.After(now) {
			jwtString = cookie.Value
		}
	}
	if jwtString == "" {
		// Don't error if the token just doesn't exist
		return zero, exp, nil
	}
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
	if info.Scopes != nil && len(info.Scopes) > 0 {
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
	isFinal() bool // True if we can clean cookies after this
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
	redirect, err := api.HydraClient.AuthAccept(ctx, api.Client, loginChallenge, accept)
	if err != nil {
		return newErrorMessage(http.StatusInternalServerError, ErrorAcceptRequestFail, "", err)
	}
	return SuccessMessage{
		LoginInfo: info,
		Final:     true,
		Redirect:  redirect,
	}
}

// consent updates the Hydra server and writes the response
func (api *Api) consent(ctx context.Context, consentChallenge string, now, exp time.Time, info LoginInfo) message {
	accept := ConsentAccept{
		Scopes: info.Scopes,
	}
	if remaining := exp.Sub(now); remaining > 0 {
		accept.RememberFor = int(remaining / time.Second)
		accept.Remember = true
	}
	redirect, err := api.HydraClient.ConsentAccept(ctx, api.Client, consentChallenge, accept)
	if err != nil {
		return newErrorMessage(http.StatusInternalServerError, ErrorAcceptConsentFail, "", err)
	}
	return SuccessMessage{
		LoginInfo: info,
		Final:     true,
		Redirect:  redirect,
	}
}

// rejectAuth updates the Hydra server and writes the response
func (api *Api) rejectAuth(ctx context.Context, loginChallenge string, loginReject ChallengeReject) message {
	redirect, err := api.HydraClient.AuthReject(ctx, api.Client, loginChallenge, loginReject)
	if err != nil {
		return newErrorMessage(http.StatusFailedDependency, ErrorRejectRequestFail, "", err)
	}
	return ErrorMessage{
		JsonError: loginReject.Json(http.StatusUnauthorized),
		Final:     true,
		Redirect:  redirect,
	}
}

// rejectConsent updates the Hydra server and writes the response
func (api *Api) rejectConsent(ctx context.Context, consentChallenge string, challengeReject ChallengeReject) message {
	redirect, err := api.HydraClient.ConsentReject(ctx, api.Client, consentChallenge, challengeReject)
	if err != nil {
		return newErrorMessage(http.StatusFailedDependency, ErrorRejectConsentFail, "", err)
	}
	return ErrorMessage{
		JsonError: challengeReject.Json(http.StatusUnauthorized),
		Final:     true,
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
	// Make sure to clean dangling cookies
	if e.isFinal() {
		removeCookie(w, CookieLoginChallenge)
		removeCookie(w, CookieConsentChallenge)
	}
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

// isFinal implements message
func (s SuccessMessage) isFinal() bool {
	return s.Final
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

// isFinal implements message
func (e ErrorMessage) isFinal() bool {
	return e.Final
}

type cookieRemoverWriter struct {
	cookieName string
	http.ResponseWriter
}

func removeCookie(w http.ResponseWriter, cookieName string) {
	// Remove the cookie before returning
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Value:    "",
	})
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
	removeCookie(c.ResponseWriter, c.cookieName)
}
