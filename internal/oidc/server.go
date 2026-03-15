package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/golang-jwt/jwt/v5"

	"github.com/maggch97/dingtalk-oidc/internal/dingtalk"
	"github.com/maggch97/dingtalk-oidc/internal/store"
)

// Server implements minimal OIDC provider bridging DingTalk login code -> OIDC code -> ID token.
type Server struct {
	Issuer                string
	ClientID              string
	ClientSecret          string
	AllowedRedirectURLs   []string
	ClaimsTransformScript string
	AuthCodes             *store.AuthCodeStore
	Pending               *store.PendingStore
	Key                   *rsa.PrivateKey
	KeyID                 string
	Provider              *dingtalk.Provider
}

func NewServer() (*Server, error) {
	issuer := os.Getenv("ISSUER")
	clientID := os.Getenv("DINGTALK_CLIENT_ID")
	clientSecret := os.Getenv("DINGTALK_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil, ErrConfigMissing
	}

	// Parse allowed redirect URLs from comma-separated env var
	var allowedRedirectURLs []string
	if allowedURLsEnv := os.Getenv("ALLOWED_REDIRECT_URLS"); allowedURLsEnv != "" {
		for _, u := range strings.Split(allowedURLsEnv, ",") {
			trimmed := strings.TrimSpace(u)
			if trimmed != "" {
				allowedRedirectURLs = append(allowedRedirectURLs, trimmed)
			}
		}
	}

	// Read claims transform script from file path specified in env var
	var claimsTransformScript string
	if scriptPath := os.Getenv("CLAIMS_TRANSFORM_SCRIPT"); scriptPath != "" {
		scriptContent, err := os.ReadFile(scriptPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read claims transform script from %s: %w", scriptPath, err)
		}
		claimsTransformScript = string(scriptContent)
		log.Printf("Loaded claims transform script from: %s", scriptPath)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Server{
		Issuer:                issuer,
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		AllowedRedirectURLs:   allowedRedirectURLs,
		ClaimsTransformScript: claimsTransformScript,
		AuthCodes:             store.NewAuthCodeStore(),
		Pending:               store.NewPendingStore(),
		Key:                   key,
		KeyID:                 "d1",
		Provider:              &dingtalk.Provider{ClientID: clientID, ClientSecret: clientSecret},
	}, nil
}

var ErrConfigMissing = &ConfigError{"missing required env (ISSUER, DINGTALK_CLIENT_ID, DINGTALK_CLIENT_SECRET)"}

type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

// RegisterHandlers registers HTTP endpoints on mux.
func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/dingtalk/callback", s.handleDingTalkCallback)
	mux.HandleFunc("/userinfo", s.handleUserInfo)
	mux.HandleFunc("/token", s.handleToken)
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	cfg := map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.Issuer + "/authorize",
		"token_endpoint":                        s.Issuer + "/token",
		"userinfo_endpoint":                     s.Issuer + "/userinfo",
		"jwks_uri":                              s.Issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nonce", "name", "picture", "email", "email_verified", "phone_number", "phone_number_verified"},
	}
	writeJSON(w, cfg)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := s.Key.Public().(*rsa.PublicKey)
	e := big.NewInt(int64(pub.E)).Bytes()
	n := pub.N.Bytes()
	jwk := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": s.KeyID,
			"e":   base64.RawURLEncoding.EncodeToString(e),
			"n":   base64.RawURLEncoding.EncodeToString(n),
		}},
	}
	writeJSON(w, jwk)
}

// /authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid&state=...&nonce=...
// Starts OIDC flow and redirects to DingTalk authorization endpoint.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID != s.ClientID {
		http.Error(w, "unauthorized_client", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !strings.HasPrefix(redirectURI, "http") {
		http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri against allowed list if configured
	if len(s.AllowedRedirectURLs) > 0 {
		allowed := false
		for _, allowedURL := range s.AllowedRedirectURLs {
			if redirectURI == allowedURL {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "redirect_uri_not_allowed", http.StatusBadRequest)
			return
		}
	}

	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		http.Error(w, "invalid_scope", http.StatusBadRequest)
		return
	}
	clientState := q.Get("state")
	nonce := q.Get("nonce")
	internal, err := s.Pending.Create(store.PendingAuth{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		OriginalState: clientState,
		Nonce:         nonce,
		Scope:         q.Get("scope"),
		CreatedAt:     time.Now(),
	})
	if err != nil {
		log.Printf("failed to create pending state: %v", err)
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	callback := strings.TrimSuffix(s.Issuer, "/") + "/dingtalk/callback"
	authURL := "https://login.dingtalk.com/oauth2/auth?client_id=" + url.QueryEscape(s.ClientID) +
		"&redirect_uri=" + url.QueryEscape(callback) +
		"&response_type=code&scope=openid&prompt=login consent&state=" + url.QueryEscape(internal)
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusFound)
}

// /dingtalk/callback?code=...&state=internalState
func (s *Server) handleDingTalkCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	pending, err := s.Pending.Consume(state)
	if err != nil {
		http.Error(w, "invalid_state", http.StatusBadRequest)
		return
	}
	sess := dingtalk.NewSession(s.Provider, code)
	user, err := sess.FetchUser(r.Context())
	if err != nil {
		log.Printf("dingtalk fetch error: %v", err)
		http.Error(w, "dingtalk_error", http.StatusBadGateway)
		return
	}
	oidcCode, err := s.AuthCodes.Create(store.AuthCodeData{UserSub: user.UnionID, User: user, ClientID: pending.ClientID, Nonce: pending.Nonce, Expiry: time.Now().Add(5 * time.Minute)})
	if err != nil {
		log.Printf("failed to create auth code: %v", err)
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	sep := "?"
	if strings.Contains(pending.RedirectURI, "?") {
		sep = "&"
	}
	loc := pending.RedirectURI + sep + "code=" + oidcCode
	if pending.OriginalState != "" {
		loc += "&state=" + url.QueryEscape(pending.OriginalState)
	}
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	clientID, clientSecret, authErr := parseClientAuth(r)
	if authErr != nil {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	if clientID != s.ClientID || clientSecret != s.ClientSecret {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	acData, err := s.AuthCodes.Consume(code)
	if err != nil {
		http.Error(w, "invalid_code", http.StatusBadRequest)
		return
	}
	// Build ID token
	claims := jwt.MapClaims{
		"iss": s.Issuer,
		"sub": acData.UserSub,
		"aud": clientID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	if acData.Nonce != "" {
		claims["nonce"] = acData.Nonce
	}
	if user, ok := acData.User.(*dingtalk.User); ok {
		if user.Nick != "" {
			claims["name"] = user.Nick
		}
		if user.AvatarURL != "" {
			claims["picture"] = user.AvatarURL
		}
		if user.Email != "" {
			claims["email"] = user.Email
			claims["email_verified"] = true
		}
		if user.Mobile != "" {
			claims["phone_number"] = user.Mobile
			claims["phone_number_verified"] = true
		}
	}

	// Apply JavaScript transformation to claims if configured
	transformedClaims, err := s.transformClaims(claims)
	if err != nil {
		log.Printf("claims transform error: %v", err)
		http.Error(w, "claims_transform_error", http.StatusInternalServerError)
		return
	}

	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, transformedClaims).SignedString(s.Key)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"access_token": idToken, // we reuse id_token as access for simplicity
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   600,
	}
	writeJSON(w, resp)
}

// handleUserInfo implements OIDC UserInfo endpoint.
// It expects Authorization: Bearer <token> where token is the (ID) access token we issued.
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "missing_authorization", http.StatusUnauthorized)
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		http.Error(w, "invalid_authorization", http.StatusUnauthorized)
		return
	}
	tokStr := parts[1]
	tok, err := jwt.Parse(tokStr, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unexpected_alg")
		}
		return &s.Key.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "invalid_claims", http.StatusUnauthorized)
		return
	}
	if claims["iss"] != s.Issuer {
		http.Error(w, "invalid_issuer", http.StatusUnauthorized)
		return
	}
	// audience may be string or array; handle string case
	switch aud := claims["aud"].(type) {
	case string:
		if aud != s.ClientID {
			http.Error(w, "invalid_aud", http.StatusUnauthorized)
			return
		}
	case []any:
		valid := false
		for _, v := range aud {
			if vs, ok := v.(string); ok && vs == s.ClientID {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid_aud", http.StatusUnauthorized)
			return
		}
	default:
		http.Error(w, "invalid_aud", http.StatusUnauthorized)
		return
	}
	if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() > int64(exp) {
		http.Error(w, "expired_token", http.StatusUnauthorized)
		return
	}
	resp := map[string]any{"sub": claims["sub"]}
	for _, k := range []string{"name", "picture", "email", "email_verified", "phone_number", "phone_number_verified"} {
		if v, ok := claims[k]; ok {
			resp[k] = v
		}
	}
	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// transformClaims applies JavaScript transformation to claims if script is configured.
// The JS script should define a function `transform(claims)` that returns modified claims.
func (s *Server) transformClaims(claims jwt.MapClaims) (jwt.MapClaims, error) {
	if s.ClaimsTransformScript == "" {
		return claims, nil
	}

	vm := goja.New()

	// Convert claims to a format goja can handle
	claimsObj := vm.NewObject()
	for k, v := range claims {
		if err := claimsObj.Set(k, v); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", k, err)
		}
	}

	// Set the claims object in the VM
	if err := vm.Set("claims", claimsObj); err != nil {
		return nil, fmt.Errorf("failed to set claims in VM: %w", err)
	}

	// Execute the script
	script := s.ClaimsTransformScript + "\ntransform(claims);"
	result, err := vm.RunString(script)
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	// Convert result back to jwt.MapClaims
	resultObj := result.Export()
	resultMap, ok := resultObj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("transform function must return an object, got %T", resultObj)
	}

	newClaims := jwt.MapClaims{}
	for k, v := range resultMap {
		newClaims[k] = v
	}

	return newClaims, nil
}

// parseClientAuth extracts client_id and client_secret following RFC 6749 section 2.3.1 (Basic auth)
// Falls back to form parameters if Authorization header absent.
func parseClientAuth(r *http.Request) (string, string, error) {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
			return "", "", fmt.Errorf("invalid_basic_header")
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", "", fmt.Errorf("bad_basic_base64")
		}
		cred := string(decoded)
		sep := strings.IndexByte(cred, ':')
		if sep < 0 {
			return "", "", fmt.Errorf("bad_basic_format")
		}
		cid := cred[:sep]
		secret := cred[sep+1:]
		if cid == "" {
			return "", "", fmt.Errorf("empty_client_id")
		}
		return cid, secret, nil
	}
	// fallback to body
	return r.Form.Get("client_id"), r.Form.Get("client_secret"), nil
}
