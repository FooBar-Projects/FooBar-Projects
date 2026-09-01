package main

import (
	"crypto/tls"
	"strings"
	"crypto/rsa"
	"strconv"
	"errors"
	"math"
	"crypto/sha256"
	"crypto/rand"
	"sync"
	"log"
	"fmt"
	"os"
	"io"
	"encoding/json"
	"encoding/base64"
	"net/http"
	"time"
	"github.com/joho/godotenv"
	"github.com/golang-jwt/jwt/v5"
)

const sessionExpirationTimeMinutes = 60 * 24 * 7 // One week

type AuthState struct {
	RandomToken string `json:randomToken`
	DeepLinkRedirect string `json:deepLinkRedirect`
}

func (as *AuthState) Clone() *AuthState {
	result := *as
	return &result
}

func (as *AuthState) Equals(other *AuthState) bool {
	if as.RandomToken != other.RandomToken {
		return false
	}

	if as.DeepLinkRedirect != other.DeepLinkRedirect {
		return false
	}

	return true
}

type Session struct {
	SessionToken string
	PKCECodeVerifier *string
	State *AuthState
	AccessToken *string
	AccessTokenExpiration *time.Time
	RefreshToken *string
	RefreshTokenExpiration *time.Time
	Expiration time.Time
}

func (s *Session) Clone() *Session {
	result := *s

	if result.State != nil {
		result.State = result.State.Clone()
	}

	return &result
}

func GeneratePKCECodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func SecureRandomString(minLength int) (string, error) {
	n_bytes := int(math.Floor((float64(minLength) - 1.0) * 3.0 / 4.0 + 1.0))
	bytes := make([]byte, n_bytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func NewSession(deepLinkRedirect string) (*Session, error) {
	sessionToken, err := SecureRandomString(32)
	if err != nil {
		return nil, err
	}
	stateRandomToken, err := SecureRandomString(32)
	if err != nil {
		return nil, err
	}
	pkceCodeVerifier, err := SecureRandomString(128)
	if err != nil {
		return nil, err
	}
	session := &Session{
		SessionToken: sessionToken,
		PKCECodeVerifier: &pkceCodeVerifier,
		State: &AuthState{
			RandomToken: stateRandomToken,
			DeepLinkRedirect: deepLinkRedirect,
		},
		Expiration: time.Now().Add(time.Duration(sessionExpirationTimeMinutes) * time.Minute),
	}

	return session, nil
}

type SessionData struct {
	mutex sync.RWMutex
	lookupTable map[string]*Session
	lookupTableToBePurged map[string]*Session
}

func NewSessionData() *SessionData {
	return &SessionData{
		lookupTable: make(map[string]*Session),
		lookupTableToBePurged: make(map[string]*Session),
	}
}

func (sessionData *SessionData) AddSession(session *Session) {
	sessionData.mutex.Lock()
	defer sessionData.mutex.Unlock()

	// Store clone in lookup table (prevents shared access outside of critical
	// section)
	sessionData.lookupTable[session.SessionToken] = session.Clone()
}

func (sessionData *SessionData) UpdateSession(session *Session) error {
	sessionData.mutex.Lock()
	defer sessionData.mutex.Unlock()

	// Verify session exists in sessionData
	_, exists := sessionData.lookupTable[session.SessionToken]
	if !exists {
		// Check to-be-purged lookup table
		_, exists = sessionData.lookupTableToBePurged[session.SessionToken]
		if !exists {
			// Session doesn't exist. Perhaps user just logged out. Return error.
			return errors.New("session no longer exists")
		}
	}

	// Store clone in lookup table (prevents shared access outside of critical
	// section)
	sessionData.lookupTable[session.SessionToken] = session.Clone()

	// If session is in lookup table to be purged, remove it
	delete(sessionData.lookupTableToBePurged, session.SessionToken)

	return nil
}

func (sessionData *SessionData) GetSession(sessionToken string) *Session {
	sessionData.mutex.Lock()
	defer sessionData.mutex.Unlock()

	session, ok := sessionData.lookupTable[sessionToken]
	if !ok {
		// Session doesn't exist. Check table to be purged.
		session, ok = sessionData.lookupTableToBePurged[sessionToken]
		if !ok {
			// Not in table to be purged, either. Return nil.
			return nil
		}

		// Session found, to be purged in next purging cycle. Check if it's
		// expired.
		if session.Expiration.Before(time.Now()) {
			// Expired. Delete it and return nil
			delete(sessionData.lookupTableToBePurged, sessionToken)
			return nil
		}

		// Not expired. Update expiration and move to non-purging lookup table
		// so that it doesn't get purged in next purging cycle (and for
		// faster subsequent lookups). Then return clone (prevents shared
		// access outside of critical section).
		session.Expiration = time.Now().Add(time.Duration(sessionExpirationTimeMinutes) * time.Minute)
		sessionData.lookupTable[sessionToken] = session
		delete(sessionData.lookupTableToBePurged, sessionToken)
		return session.Clone()
	}

	// Session found in regular (non-purging) lookup table. Check for
	// expiration.
	if session.Expiration.Before(time.Now()) {
		// Session is expired. Delete it and return nil
		delete(sessionData.lookupTable, sessionToken)
		return nil
	}

	// Session is not expired. Update expiration and return clone (prevents
	// shared access outside of critical section).
	session.Expiration = time.Now().Add(time.Duration(sessionExpirationTimeMinutes) * time.Minute)

	return session.Clone()
}

func (sessionData *SessionData) DeleteSession(sessionToken string) {
	sessionData.mutex.Lock()
	defer sessionData.mutex.Unlock()

	delete(sessionData.lookupTable, sessionToken)
	delete(sessionData.lookupTableToBePurged, sessionToken)
}

// Runs every purge cycle (interval = session token expiration time); purges
// tokens from server memory that haven't been touched in the last cycle
func (sessionData *SessionData) PurgeExpiredSessions() {
	sessionData.mutex.Lock()
	defer sessionData.mutex.Unlock()

	// Move lookupTable to lookupTableToBePurged, deleting current
	// lookupTableToBePurged in the process (it was created in the previous
	// purge cycle, so all the sessions still in it haven't been touched
	// for one full purge cycle, hence they're guaranteed to be expired
	// and should be purged).
	sessionData.lookupTableToBePurged = sessionData.lookupTable

	// Bind lookupTable to new, fresh map. Sessions in the to-be-purged
	// table will be moved here dynamically as they're re-used, or purged
	// in the next purge cycle if they aren't reused
	sessionData.lookupTable = make(map[string]*Session)
}

type SharedJWT struct {
	mutex sync.RWMutex
	privateKey *rsa.PrivateKey
	clientId string
	cachedJWT *string
	expiration *time.Time
}

func (sharedJWT *SharedJWT) Get() (*string, error) {
	sharedJWT.mutex.Lock()
	defer sharedJWT.mutex.Unlock()
	
	if sharedJWT.cachedJWT == nil || sharedJWT.expiration.Before(time.Now()) {
		// Cached JWT is expired or nil. Create and sign new one.
		issuedAt := time.Now().Add(-1 * time.Minute)
		expiresAt := issuedAt.Add(10 * time.Minute)
		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt: jwt.NewNumericDate(issuedAt),
			Issuer: sharedJWT.clientId,
		}

		token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

		tokenString, err := token.SignedString(sharedJWT.privateKey)
		if err != nil {
			return nil, err
		}
		
		sharedJWT.cachedJWT = &tokenString
		// Expire in cache 10 seconds before JWT actually expires, avoiding
		// use of expired token due to latency
		sharedJWTExpiration := expiresAt.Add(-10 * time.Second)
		sharedJWT.expiration = &sharedJWTExpiration
	}

	// Return cached JWT string (pointer, but strings are immutable, so
	// no concern of shared mutable state)
	return sharedJWT.cachedJWT, nil
}

type HandlerContext struct {
	client *http.Client
	githubClientId string
	githubClientSecret string
	githubOAuthRedirectURI string
	webFrontendHostname string
	sessionData SessionData
	sharedJWT SharedJWT
}

func NewHandlerContext(
		githubClientId string,
		githubClientSecret string,
		githubClientPrivateKey *rsa.PrivateKey,
		githubOAuthRedirectURI string,
		webFrontendHostname string) HandlerContext {
	_, webFrontendHostnameWithoutProtocol, found := strings.Cut(webFrontendHostname, "://")
	if !found {
		webFrontendHostnameWithoutProtocol = webFrontendHostname
	}
	_, webFrontendHostnameWithoutWWW, found := strings.Cut(webFrontendHostnameWithoutProtocol, "www.")
	if !found {
		webFrontendHostnameWithoutWWW = webFrontendHostnameWithoutProtocol
	}
	
	return HandlerContext{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		githubClientId: githubClientId,
		githubClientSecret: githubClientSecret,
		githubOAuthRedirectURI: githubOAuthRedirectURI,
		webFrontendHostname: webFrontendHostnameWithoutWWW,
		sessionData: *NewSessionData(),
		sharedJWT: SharedJWT{
			privateKey: githubClientPrivateKey,
			clientId: githubClientId,
		},
	}
}

func (h *HandlerContext) PurgeExpiredSessionsLoop() {
	ticker := time.NewTicker(time.Duration(sessionExpirationTimeMinutes) * time.Minute)
	for range ticker.C {
		h.sessionData.PurgeExpiredSessions()
	}
}

type GenAuthTokensServerRequest struct {
	ClientId string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

type AuthServerAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	AccessTokenExpiresIn int `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	RefreshTokenExpiresIn int `json:"refresh_token_expires_in"`
}

// /token endpoint. Exchanges auth code for auth tokens using client secret.
// Stores tokens in server-side session. Browser can then later send GET
// to /access-token to request the access token (existing or new if existing is
// expired) to store in local JS memory for authenticating subsequent
// in-page requests. This is the token-mediating backend pattern from
// RFC 10017
func (h *HandlerContext) tokenHandler(w http.ResponseWriter, r *http.Request) {
	// Get auth code and state query parameters
	authCodeQueryParamValue := r.URL.Query().Get("code")
	stateQueryParamValue := r.URL.Query().Get("state")
	if authCodeQueryParamValue == "" || stateQueryParamValue == "" {
		fmt.Println("/token request missing either code or state query parameter")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Get session token cookie
	sessionTokenCookie, err := r.Cookie("session_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			fmt.Println("/token request is missing session_token cookie")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			fmt.Println("Internal error: /token handler failed to retrieve session_token cookie")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// Look up session
	session := h.sessionData.GetSession(sessionTokenCookie.Value)
	if session == nil {
		fmt.Println("/token request given invalid or expired session token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check if session has PKCE verifier and auth state
	if session.PKCECodeVerifier == nil || session.State == nil {
		// Missing code verifier / auth state. Perhaps this session has
		// already completed the auth flow.
		fmt.Println("/token request given session token for session with missing PKCE code verifier or state")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Verify state query param matches state cookie (ensures browser session
	// that started login flow is same browser session making this request;
	// arguably unnecessary since PKCE code verifier is bound to session as
	// well, so PKCE verification will fail at auth server if the sessions
	// are mismatched. Still, defense in depth.)
	stateQueryParamBytes, err := base64.RawURLEncoding.DecodeString(stateQueryParamValue)
	if err != nil {
		fmt.Println("/token request state query parameter cannot be decoded (invalid base64url)")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	var stateQueryParamObj AuthState
	err = json.Unmarshal(stateQueryParamBytes, &stateQueryParamObj)
	if err != nil {
		fmt.Println("/token request state query parameter cannot be decoded (invalid JSON)")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	if !stateQueryParamObj.Equals(session.State) {
		fmt.Println("/token request given state that doesn't match session")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Request tokens from auth server.
	serverRequest, err := http.NewRequest(
		"POST",
		fmt.Sprintf(
			"https://github.com/login/oauth/access_token?" +
				"client_id=%s&client_secret=%s" +
				"&code=%s&redirect_uri=%s&code_verifier=%s",
			h.githubClientId,
			h.githubClientSecret,
			authCodeQueryParamValue,
			h.githubOAuthRedirectURI,
			*(session.PKCECodeVerifier),
		),
		nil,
	)

	if err != nil {
		fmt.Printf("Error creating token request: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	serverRequest.Header.Set("Content-Type", "application/json")
	serverRequest.Header.Set("Accept", "application/vnd.github+json")

	response, err := h.client.Do(serverRequest)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Printf("Got HTTP status %d when exchanging code for access token\n", response.StatusCode);
		w.WriteHeader(response.StatusCode)
		return
	}

	var responseObj AuthServerAccessTokenResponse
	err = json.NewDecoder(response.Body).Decode(&responseObj)
	if err != nil {
		fmt.Printf("Error decoding auth server response: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Persist auth tokens in server-side session data
	session.AccessToken = &responseObj.AccessToken
	accessTokenExpiration := time.Now().Add(time.Duration(responseObj.AccessTokenExpiresIn - 20) * time.Second)
	session.AccessTokenExpiration = &accessTokenExpiration
	session.RefreshToken = &responseObj.RefreshToken
	refreshTokenExpiration := time.Now().Add(time.Duration(responseObj.RefreshTokenExpiresIn - 20) * time.Second)
	session.RefreshTokenExpiration = &refreshTokenExpiration

	// Delete session's State and PKCECodeVerifier
	deepLinkRedirect := session.State.DeepLinkRedirect
	session.State = nil
	session.PKCECodeVerifier = nil

	// Push session changes to lookup table
	err = h.sessionData.UpdateSession(session)
	if err != nil {
		// Session disappeared. Perhaps user just logged out suddenly.
		fmt.Println("/token: session was deleted suddenly")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Redirect user to deep link redirect URL
	http.Redirect(w, r, deepLinkRedirect, http.StatusTemporaryRedirect)
}

type StartSessionRequestBody struct {
	DeepLinkRedirect string `json:"deep_link_redirect"`
}

type StartSessionResponseBody struct {
	OAuthLoginURI string `json:"oauth_login_uri"`
}

// /start-session endpoint (establishes session, including state + pkce code
// verifier, and redirects user to GitHub OAuth login page)
func (h *HandlerContext) startSessionHandler(w http.ResponseWriter, r *http.Request) {
	// Verify Content-Type header
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		fmt.Printf("/start-session expected Content-Type to be \"application/json\", but got \"%s\"\n", contentType)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get deep_link_redirect from request body
	var requestBody StartSessionRequestBody
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		fmt.Println("/start-session failed to parse post body")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Check for session token cookie
	sessionTokenCookie, err := r.Cookie("session_token")
	if err == nil {
		// Session token found. Delete session if it exists before proceeding.
		h.sessionData.DeleteSession(sessionTokenCookie.Value)
	} else if !errors.Is(err, http.ErrNoCookie) {
		fmt.Println("Internal error: /token handler failed to retrieve session_token cookie")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create new session.
	session, err := NewSession(requestBody.DeepLinkRedirect)
	if err != nil {
		fmt.Println("Internal error: /start-session handler failed to create session")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Add session to shared lookup table
	h.sessionData.AddSession(session)

	// Convert state to base64url string
	stateJsonBytes, err := json.Marshal(session.State)
	if err != nil {
		fmt.Println("Internal error: /start-session handler failed to JSON-marshal auth state")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	stateBase64url := base64.RawURLEncoding.EncodeToString(stateJsonBytes)

	// Generate PKCE code challenge
	codeChallenge := GeneratePKCECodeChallenge(*session.PKCECodeVerifier)

	// Notify app to redirect user to GitHub OAuth login page
	redirectURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s" +
			"&state=%s&redirect_uri=%s&code_challenge=%s" +
			"&code_challenge_method=S256",
		h.githubClientId,
		stateBase64url,
		h.githubOAuthRedirectURI,
		codeChallenge,
	)
	w.Header().Set(
		"Set-Cookie",
		fmt.Sprintf(
			"session_token=%s; Max-Age=%d; Path=/; SameSite=Lax; HttpOnly; Secure",
			session.SessionToken,
			int64(session.Expiration.Sub(time.Now()).Seconds()),
		),
	)

	payload := StartSessionResponseBody{
		OAuthLoginURI: redirectURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(payload)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

// /access-token endpoint (client provides session cookie and retrieves
// the access token associated with their session, refreshed if appropriate).
func (h *HandlerContext) accessTokenHandler(w http.ResponseWriter, r *http.Request) {
	// CORS header
	origin := r.Header.Get("Origin")
	_, withoutProtocol, found := strings.Cut(origin, "://")
	if !found {
		withoutProtocol = origin
	}
	_, withoutWWW, found := strings.Cut(withoutProtocol, "www.")
	if !found {
		withoutWWW = withoutProtocol
	}
	if withoutWWW == h.webFrontendHostname {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	// Get session token cookie
	sessionTokenCookie, err := r.Cookie("session_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			fmt.Println("/access-token request is missing session_token cookie")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			fmt.Println("Internal error: /access-token handler failed to retrieve session_token cookie")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// Look up session
	session := h.sessionData.GetSession(sessionTokenCookie.Value)
	if session == nil {
		fmt.Println("/access-token request given invalid or expired session token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Verify refresh token exists in session
	if session.RefreshToken == nil {
		fmt.Println("/access-token request given session_token for session with no server-side refresh token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check for expiration
	if session.AccessToken == nil || session.AccessTokenExpiration.Before(time.Now()) {
		// Access token expired. Check if refresh token is expired.
		if session.RefreshTokenExpiration.Before(time.Now()) {
			// Expired. User must redo auth flow. Send HTTP 401
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Refresh token is still good. Refresh both tokens.
		refreshRequest, err := http.NewRequest(
			"POST",
			fmt.Sprintf(
				"https://github.com/login/oauth/access_token?" +
					"client_id=%s&client_secret=%s" +
					"&grant_type=refresh_token&refresh_token=%s",
				h.githubClientId,
				h.githubClientSecret,
				*session.RefreshToken,
			),
			nil,
		)
		if err != nil {
			fmt.Printf("Error creating refresh request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		refreshRequest.Header.Set("Accept", "application/vnd.github+json")

		response, err := h.client.Do(refreshRequest)
		if err != nil {
			fmt.Printf("Refresh request failed: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusUnauthorized {
			fmt.Printf("Got 401 HTTP status when refreshing auth tokens\n");
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if response.StatusCode < 200 || response.StatusCode >= 300 {
			fmt.Printf("Got HTTP status %d when refreshing auth tokens\n", response.StatusCode);
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var responseObj AuthServerAccessTokenResponse
		err = json.NewDecoder(response.Body).Decode(&responseObj)
		if err != nil {
			fmt.Printf("Error decoding auth server response: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		
		// Store new tokens in session and push to lookup table
		session.AccessToken = &responseObj.AccessToken
		accessTokenExpiration := time.Now().Add(time.Duration(responseObj.AccessTokenExpiresIn - 20) * time.Second)
		session.AccessTokenExpiration = &accessTokenExpiration
		session.RefreshToken = &responseObj.RefreshToken
		refreshTokenExpiration := time.Now().Add(time.Duration(responseObj.RefreshTokenExpiresIn - 20) * time.Second)
		session.RefreshTokenExpiration = &refreshTokenExpiration
		h.sessionData.UpdateSession(session)
		err = h.sessionData.UpdateSession(session)
		if err != nil {
			// Session disappeared. Perhaps user just logged out suddenly.
			fmt.Println("/access-token: session was deleted suddenly")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// Access token refreshed (or wasn't expired). Send access token
	payload := AccessTokenResponse{
		AccessToken: *session.AccessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(payload)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

const htmlContent = `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Logout</title>
	</head>
	<body>
		<p>Successfully logged out.</p>
	</body>
	</html>
`

// /logout endpoint (deletes session and notifies client to delete
// session token cookie)
func (h *HandlerContext) logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get session token cookie
	sessionTokenCookie, err := r.Cookie("session_token")
	if err == nil {
		// Session token cookie exists. Notify client to delete it.
		w.Header().Set("Set-Cookie", "session_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=Lax; HttpOnly; Secure")
		// Delete sever-side session if it exists.
		h.sessionData.DeleteSession(sessionTokenCookie.Value)
	} else if !errors.Is(err, http.ErrNoCookie) {
		fmt.Println("Internal error: /logout handler failed to retrieve session_token cookie")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	
	// Send small logout html page back
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, htmlContent)
}

type VerifyInstallationRequestBody struct {
	OrganizationName string `json:"organization_name"`
	InstallationId string `json:"installation_id"`
}

type VerifyInstallationResponseBody struct {
	Status string `json:"status"`
}

type GetInstallationResponseAccount struct {
	Login string `json:"login"`
}

type GetInstallationResponseBody struct {
	Account GetInstallationResponseAccount `json:"account"`
}

type GetInstallationAccessTokenResponseBody struct {
	Token string `json:"token"`
	RepositorySelection string `json:"repository_selection"`
}

type GetInstallationRepositoriesResponseRepository struct {
	Name string `json:"name"`
}

type GetInstallationRepositoriesResponseBody struct {
	Repositories []GetInstallationRepositoriesResponseRepository `json:"repositories"`
}

// /verify-installation endpoint (checks whether app installation is configured
// properly)
func (h *HandlerContext) verifyInstallationHandler(w http.ResponseWriter, r *http.Request) {
	// Get organization name and installation ID query params
	organizationNameQueryParamValue := r.URL.Query().Get("organization-name")
	installationIdQueryParamValue := r.URL.Query().Get("installation-id")
	if organizationNameQueryParamValue == "" || installationIdQueryParamValue == "" {
		fmt.Println("/verify-installation request missing either organization-name or installation-id query parameter")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// Get auth app JWT
	jwtString, err := h.sharedJWT.Get()
	if err != nil {
		fmt.Println("/verify-installation failed to sign JWT")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Get installation account
	serverRequest, err := http.NewRequest(
		"GET",
		fmt.Sprintf(
			"https://api.github.com/app/installations/%s",
			installationIdQueryParamValue,
		),
		nil,
	)

	if err != nil {
		fmt.Printf("Error creating installation request: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	serverRequest.Header.Set("Accept", "application/vnd.github+json")
	serverRequest.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	serverRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *jwtString))

	response, err := h.client.Do(serverRequest)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	if response.StatusCode == 404 {
		fmt.Println("Got HTTP 404 when requesting installation")
		w.WriteHeader(http.StatusNotFound)
		return
	} else if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Printf("Got HTTP status %d when requesting installation\n", response.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var getInstallationResponseBody GetInstallationResponseBody 
	err = json.NewDecoder(response.Body).Decode(&getInstallationResponseBody)
	if err != nil {
		fmt.Printf("Error decoding installation response body: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Verify installation account matches what was sent in request
	if !strings.EqualFold(getInstallationResponseBody.Account.Login, organizationNameQueryParamValue) {
		// Organization name doesn't match. Return status "bad-account"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		payload := VerifyInstallationResponseBody{
			Status: "bad-account",
		}
		err = json.NewEncoder(w).Encode(payload)
		if err != nil {
			fmt.Printf("Error marshalling JSON: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	// Organization name matches. Get installation access token
	serverRequest, err = http.NewRequest(
		"POST",
		fmt.Sprintf(
			"https://api.github.com/app/installations/%s/access_tokens",
			installationIdQueryParamValue,
		),
		nil,
	)

	if err != nil {
		fmt.Printf("Error creating installation access token request: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	serverRequest.Header.Set("Accept", "application/vnd.github+json")
	serverRequest.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	serverRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *jwtString))

	response, err = h.client.Do(serverRequest)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Printf("Got HTTP status %d when requesting installation access token\n", response.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var getInstallationAccessTokenResponseBody GetInstallationAccessTokenResponseBody 
	err = json.NewDecoder(response.Body).Decode(&getInstallationAccessTokenResponseBody)
	if err != nil {
		fmt.Printf("Error decoding installation access token response body: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}


	// Verify repository_selection is 'selected'
	if getInstallationAccessTokenResponseBody.RepositorySelection != "selected" {
		// Bad repository selection
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		payload := VerifyInstallationResponseBody{
			Status: "bad-repository-selection",
		}
		err = json.NewEncoder(w).Encode(payload)
		if err != nil {
			fmt.Printf("Error marshalling JSON: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	// Get selected repositories
	serverRequest, err = http.NewRequest(
		"GET",
		"https://api.github.com/installation/repositories",
		nil,
	)

	if err != nil {
		fmt.Printf("Error creating installation repositories request: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	serverRequest.Header.Set("Accept", "application/vnd.github+json")
	serverRequest.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	serverRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", getInstallationAccessTokenResponseBody.Token))

	response, err = h.client.Do(serverRequest)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Printf("Got HTTP status %d when requesting installation repositories\n", response.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var getInstallationRepositoriesResponseBody GetInstallationRepositoriesResponseBody 
	err = json.NewDecoder(response.Body).Decode(&getInstallationRepositoriesResponseBody)
	if err != nil {
		fmt.Printf("Error decoding installation repositories response body: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Verify selected repositories only contains 'backend-workflows'
	if len(getInstallationRepositoriesResponseBody.Repositories) != 1 ||
			getInstallationRepositoriesResponseBody.Repositories[0].Name !=
				"backend-workflows" {
		// Bad selected repositories
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		payload := VerifyInstallationResponseBody{
			Status: "bad-selected-repositories",
		}
		err = json.NewEncoder(w).Encode(payload)
		if err != nil {
			fmt.Printf("Error marshalling JSON: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}

	// Installation checks out. Return verified status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	payload := VerifyInstallationResponseBody{
		Status: "verified",
	}
	err = json.NewEncoder(w).Encode(payload)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}


type DynamicSSLCertificate struct{
	mutex sync.RWMutex
	cert *tls.Certificate
}


func (dynCert *DynamicSSLCertificate) Reload(certPath string, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}

	dynCert.mutex.Lock()
	defer dynCert.mutex.Unlock()
	dynCert.cert = &cert
	return nil
}


func NewDynamicSSLCertificate(certPath string, keyPath string) (*DynamicSSLCertificate, error) {
	res := DynamicSSLCertificate{}
	err := res.Reload(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &res, nil
}


func (cert *DynamicSSLCertificate) Get(
		helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert.mutex.Lock()
	defer cert.mutex.Unlock()
	return cert.cert, nil
}


func updateDynamicSSLCertificateLoop(
		cert *DynamicSSLCertificate,
		certPath string,
		keyPath string,
		interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		err := cert.Reload(certPath, keyPath)
		if err != nil {
			log.Printf("Error reloading SSL cert: %v\n", err)
		}
	}
}


func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	githubAuthClientId := os.Getenv("FOOBAR_PROJECTS_GITHUB_AUTH_CLIENT_ID")
	githubAuthClientSecret := os.Getenv("FOOBAR_PROJECTS_GITHUB_AUTH_CLIENT_SECRET")
	githubAuthClientPrivateKey := os.Getenv("FOOBAR_PROJECTS_GITHUB_AUTH_CLIENT_PRIVATE_KEY")
	githubOAuthRedirectURI := os.Getenv("FOOBAR_PROJECTS_GITHUB_OAUTH_REDIRECT_URI")
	webFrontendHostname := os.Getenv("FOOBAR_PROJECTS_WEB_FRONTEND_HOSTNAME")
	networkInterface := os.Getenv("FOOBAR_PROJECTS_AUTH_SERVER_INTERFACE")
	portString := os.Getenv("FOOBAR_PROJECTS_AUTH_SERVER_PORT")
	sslCertPath := os.Getenv("FOOBAR_PROJECTS_AUTH_SSL_CERT_PATH")
	sslKeyPath := os.Getenv("FOOBAR_PROJECTS_AUTH_SSL_KEY_PATH")
	sslCertUpdateIntervalMinutesString := os.Getenv("FOOBAR_PROJECTS_AUTH_SSL_CERT_UPDATE_INTERVAL_MINUTES")

	if githubAuthClientId == "" {
		log.Fatal("FOOBAR_PROJECTS_GITHUB_AUTH_CLIENT_ID is not set or is empty")
	}

	if githubAuthClientSecret == "" {
		log.Fatal("FOOBAR_PROJECTS_GITHUB_AUTH_CLIENT_SECRET is not set or is empty")
	}

	if githubAuthClientPrivateKey == "" {
		log.Fatal("FOOBAR_PROJECTS_GITHUB_AUTH_CLIENT_PRIVATE_KEY is not set or is empty")
	}

	jwtSignKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(githubAuthClientPrivateKey))
	if err != nil {
		log.Fatal("Failed to parse auth client private key")
	}

	if githubOAuthRedirectURI == "" {
		log.Fatal("FOOBAR_PROJECTS_GITHUB_OAUTH_REDIRECT_URI is not set or is empty")
	}

	if webFrontendHostname == "" {
		log.Fatal("FOOBAR_PROJECTS_WEB_FRONTEND_HOSTNAME is not set or is empty")
	}

	if networkInterface == "" {
		log.Print("FOOBAR_PROJECTS_AUTH_SERVER_INTERFACE is not set or is empty. Binding auth server to any / all available network interfaces.")
	}

	if portString == "" {
		portString = "443"
		log.Println("FOOBAR_PROJECTS_AUTH_SERVER_PORT is not set or is empty. " +
			"Defaulting to port 443.")
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		log.Fatal(
			fmt.Sprintf(
				"FOOBAR_PROJECTS_AUTH_SERVER_PORT has non-integer value %s",
				portString,
			),
		)
	}

	if sslCertPath == "" {
		log.Fatal("FOOBAR_PROJECTS_AUTH_SSL_CERT_PATH is not set or is empty")
	}

	if sslKeyPath == "" {
		log.Fatal("FOOBAR_PROJECTS_AUTH_SSL_KEY_PATH is not set or is empty")
	}

	if sslCertUpdateIntervalMinutesString == "" {
		sslCertUpdateIntervalMinutesString = "1440"
		log.Println("FOOBAR_PROJECTS_AUTH_SSL_CERT_UPDATE_INTERVAL_MINUTES " + 
			"is not set or is empty. Defaulting to 1440.")
	}
	sslCertUpdateIntervalMinutes, err :=
		strconv.Atoi(sslCertUpdateIntervalMinutesString)
	if err != nil {
		log.Fatal(
			fmt.Sprintf(
				"FOOBAR_PROJECTS_AUTH_SSL_CERT_UPDATE_INTERVAL_MINUTES " +
					"has non-integer value %s",
				sslCertUpdateIntervalMinutes,
			),
		)
	}

	mux := http.NewServeMux()

	handlerContext := NewHandlerContext(
		githubAuthClientId,
		githubAuthClientSecret,
		jwtSignKey,
		githubOAuthRedirectURI,
		webFrontendHostname,
	)
	go handlerContext.PurgeExpiredSessionsLoop()

	mux.HandleFunc("POST /start-session", handlerContext.startSessionHandler)
	mux.HandleFunc("GET /token", handlerContext.tokenHandler)
	mux.HandleFunc("POST /access-token", handlerContext.accessTokenHandler)
	mux.HandleFunc("POST /logout", handlerContext.logoutHandler)
	mux.HandleFunc("GET /verify-installation", handlerContext.verifyInstallationHandler)

	sslCert, err := NewDynamicSSLCertificate(sslCertPath, sslKeyPath)
	if err != nil {
		log.Fatal("Failed to load SSL certificate at startup")
	}

	go updateDynamicSSLCertificateLoop(
		sslCert,
		sslCertPath,
		sslKeyPath,
		time.Duration(sslCertUpdateIntervalMinutes) * time.Minute,
	)

	server := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		Handler: mux,
		ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout: 15 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: sslCert.Get,
		},
	}

	fmt.Printf("Server starting on port %d\n", port)
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
