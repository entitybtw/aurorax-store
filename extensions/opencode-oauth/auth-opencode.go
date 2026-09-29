// addon-kind: auth
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// extID is the extension that ships this addon. Ownership, endpoints and
// scopes all come from that extension's manifest — nothing is hardcoded.
const extID = "opencode-oauth"

const (
	extensionsListPath  = "configs/extensions.json"
	overridesListPath   = "configs/provider-overrides.json"
	sidecarDefaultsPath = "configs/sidecar-overrides.json"
	tokenDataDir        = "data"
	refreshSkew         = 5 * time.Minute
)

var (
	cfgMu     sync.Mutex
	pendingMu sync.Mutex
	pending   = map[string]*pendingAuth{}
)

func UI() string {
	return `{"settings_tabs":[{"id":"oauth-device","label":"Link OpenCode account","icon":"key","order":10,"blocks":[{"kind":"heading","text":"Link your OpenCode account (device flow)"},{"kind":"text","text":"This flow is installed by the CLI OAuth extension — the gateway core ships no provider endpoints. Start a device code, open the verification URL in a browser, then paste the code back on the Providers page."},{"kind":"list","items":["Open Providers, pick a provider with external auth","Choose Link OpenCode account — the gateway starts a device code request","Open the verification URL shown there and approve","The stored token then feeds upstream requests automatically"]},{"kind":"kv","kv":[{"k":"Authorization server","v":"https://opencode.ai/console"},{"k":"Client ID","v":"opencode-cli"},{"k":"Verification base","v":"https://opencode.ai"},{"k":"Grant","v":"urn:ietf:params:oauth:grant-type:device_code"}]}]}]}`
}

// ---------------------------------------------------------------------------
// generic helpers

func errResp(format string, args ...any) string {
	return objJSON(map[string]any{"error": fmt.Sprintf(format, args...)})
}

func skipResp(provider string) string {
	return objJSON(map[string]any{
		"error":    "provider not found or external auth not configured: " + provider,
		"skip":     true,
		"provider": provider,
	})
}

func objJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"encode failed"}`
	}
	return string(b)
}

func inMap(payload string) (map[string]any, bool) {
	var m map[string]any
	if err := json.Unmarshal([]byte(payload), &m); err != nil || m == nil {
		return map[string]any{}, false
	}
	return m, true
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func trimSlash(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

func readJSON(path string, out any) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(data, out) == nil
}

// safeTokenName keeps provider names inside a single path segment.
func safeTokenName(provider string) string {
	var b strings.Builder
	for _, r := range provider {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// extension manifest / auth block

type authConfig struct {
	Server           string
	ClientID         string
	VerificationBase string
	UserAgent        string
	Scope            string
	Grant            string
	AuthorizeURL     string
	TokenURL         string
	TokenStyle       string
	Scopes           string
	StateIsVerifier  bool
	RedirectURI      string
}

func manifestList() []map[string]any {
	var asList []map[string]any
	if readJSON(extensionsListPath, &asList) {
		return asList
	}
	var wrapped struct {
		Extensions []map[string]any `json:"extensions"`
	}
	if readJSON(extensionsListPath, &wrapped) {
		return wrapped.Extensions
	}
	return nil
}

func findExtension(id string) map[string]any {
	for _, e := range manifestList() {
		if str(e["id"]) == id {
			return e
		}
	}
	return nil
}

// ownManifest returns this addon's extension record (nil = not applied).
func ownManifest() map[string]any {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return findExtension(extID)
}

func blockAuth(ext map[string]any) map[string]any {
	if b, ok := ext["auth"].(map[string]any); ok && len(b) > 0 {
		return b
	}
	// Legacy manifest key (pre-rename deployments).
	if b, ok := ext["oauth"].(map[string]any); ok && len(b) > 0 {
		return b
	}
	return nil
}

func overrideField(field string) string {
	var list []map[string]any
	if !readJSON(overridesListPath, &list) {
		return ""
	}
	for _, o := range list {
		if !externalish(str(o["auth_method"])) {
			continue
		}
		if v := str(o[field]); v != "" {
			return v
		}
	}
	return ""
}

func sidecarField(field string) string {
	var m map[string]any
	if !readJSON(sidecarDefaultsPath, &m) {
		return ""
	}
	return str(m[field])
}

func externalish(authMethod string) bool {
	switch strings.ToLower(authMethod) {
	case "external", "oauth":
		return true
	}
	return false
}

// loadAuth builds the auth config for this addon: manifest first, override
// files only as fallbacks for legacy deployments.
func loadAuth() (authConfig, bool) {
	ext := ownManifest()
	if ext == nil {
		return authConfig{}, false
	}
	cfg := authConfig{}
	if b := blockAuth(ext); b != nil {
		cfg.Server = str(b["server"])
		cfg.ClientID = str(b["client_id"])
		cfg.VerificationBase = str(b["verification_base"])
		cfg.UserAgent = str(b["user_agent"])
		cfg.Scope = str(b["scope"])
		cfg.Grant = strings.ToLower(str(b["grant"]))
		cfg.AuthorizeURL = str(b["authorize_url"])
		cfg.TokenURL = str(b["token_url"])
		cfg.TokenStyle = str(b["token_style"])
		cfg.Scopes = str(b["scopes"])
		cfg.StateIsVerifier, _ = b["state_is_verifier"].(bool)
		cfg.RedirectURI = str(b["redirect_uri"])
	}
	if cfg.Server == "" {
		cfg.Server = overrideField("oauth_server")
	}
	if cfg.Server == "" {
		cfg.Server = sidecarField("oauth_server")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = overrideField("oauth_client_id")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = sidecarField("oauth_client_id")
	}
	if cfg.VerificationBase == "" {
		cfg.VerificationBase = overrideField("oauth_verification_base")
	}
	if cfg.Grant == "" {
		cfg.Grant = "device"
	}
	if cfg.Grant == "authorization_code" {
		return cfg, true
	}
	if cfg.Server == "" || cfg.ClientID == "" {
		return cfg, false
	}
	return cfg, true
}

func (c authConfig) httpc() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func (c authConfig) applyUA(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
}

// ---------------------------------------------------------------------------
// provider ownership

func providerRecords() []map[string]any {
	var list []map[string]any
	if !readJSON(overridesListPath, &list) {
		return nil
	}
	return list
}

func extMatchesProvider(ext map[string]any, rec map[string]any) bool {
	if b, ok := ext["provides"].(map[string]any); ok {
		if types, ok := b["provider_types"].([]any); ok {
			pt := strings.ToLower(str(rec["type"]))
			for _, t := range types {
				if pt != "" && pt == strings.ToLower(str(t)) {
					return true
				}
			}
		}
	}
	if extBase := trimSlash(str(ext["base_url"])); extBase != "" {
		if trimSlash(str(rec["base_url"])) == extBase {
			return true
		}
	}
	return false
}

func extHasExplicitRules(ext map[string]any) bool {
	if str(ext["base_url"]) != "" {
		return true
	}
	if b, ok := ext["provides"].(map[string]any); ok {
		if types, ok := b["provider_types"].([]any); ok {
			return len(types) > 0
		}
	}
	return false
}

// ownedProviders lists the provider records this addon is responsible for.
func ownedProviders() []map[string]any {
	own := ownManifest()
	if own == nil {
		return nil
	}
	var others []map[string]any
	for _, e := range manifestList() {
		if str(e["id"]) == extID {
			continue
		}
		if extHasExplicitRules(e) {
			others = append(others, e)
		}
	}
	var out []map[string]any
	for _, rec := range providerRecords() {
		if !externalish(str(rec["auth_method"])) {
			continue
		}
		if extMatchesProvider(own, rec) {
			out = append(out, rec)
			continue
		}
		if extHasExplicitRules(own) {
			continue
		}
		// No explicit rules in my own extension: only take providers that no
		// rule-bearing extension claims.
		claimed := false
		for _, o := range others {
			if extMatchesProvider(o, rec) {
				claimed = true
				break
			}
		}
		if !claimed {
			out = append(out, rec)
		}
	}
	return out
}

func providerOwned(name string) (map[string]any, bool) {
	for _, rec := range ownedProviders() {
		if str(rec["name"]) == name {
			return rec, true
		}
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// authorization-code + PKCE (RFC 7636)

type pendingAuth struct {
	cfg       authConfig
	verifier  string
	state     string
	expiresAt time.Time
}

func generateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func challengeS256(verifier string) (string, error) {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func authCodeStart(cfg authConfig) (map[string]any, error) {
	cfg.AuthorizeURL = strings.TrimSpace(cfg.AuthorizeURL)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	if cfg.AuthorizeURL == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("authorization_code not configured (apply an extension that supplies authorize_url/token_url/client_id)")
	}
	redirect := cfg.RedirectURI
	if redirect == "" {
		redirect = "http://127.0.0.1:54545/callback"
	}
	tokenStyle := cfg.TokenStyle
	if tokenStyle == "" {
		tokenStyle = "json"
	}
	verifier, err := generateVerifier()
	if err != nil {
		return nil, err
	}
	challenge, err := challengeS256(verifier)
	if err != nil {
		return nil, err
	}
	state, err := generateState()
	if err != nil {
		return nil, err
	}
	if cfg.StateIsVerifier {
		state = verifier
	}
	u, err := url.Parse(cfg.AuthorizeURL)
	if err != nil {
		return nil, fmt.Errorf("invalid authorize_url: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	if scopes := strings.TrimSpace(cfg.Scopes); scopes != "" {
		q.Set("scope", scopes)
	}
	u.RawQuery = q.Encode()

	cfg.RedirectURI = redirect
	cfg.TokenStyle = tokenStyle
	expiresIn := 600
	pendingMu.Lock()
	pending[state] = &pendingAuth{
		cfg:       cfg,
		verifier:  verifier,
		state:     state,
		expiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
	for k, p := range pending {
		if time.Now().After(p.expiresAt) {
			delete(pending, k)
		}
	}
	pendingMu.Unlock()

	return map[string]any{
		"authorize_url": u.String(),
		"state":         state,
		"redirect_uri":  redirect,
		"expires_in":    expiresIn,
		"grant":         "authorization_code",
	}, nil
}

func tokenRequest(cfg authConfig, fields map[string]string) (*tokenResponse, error) {
	var body []byte
	var contentType string
	switch strings.ToLower(strings.TrimSpace(cfg.TokenStyle)) {
	case "form":
		v := url.Values{}
		for k, val := range fields {
			v.Set(k, val)
		}
		body = []byte(v.Encode())
		contentType = "application/x-www-form-urlencoded"
	default:
		var err error
		body, err = json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		contentType = "application/json"
	}
	req, err := http.NewRequest("POST", cfg.TokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	cfg.applyUA(req)
	resp, err := cfg.httpc().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, string(raw))
	}
	var tok tokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	return &tok, nil
}

func authCodeComplete(state, code string) (*tokenResponse, error) {
	state = strings.TrimSpace(state)
	code = strings.TrimSpace(code)
	if state == "" || code == "" {
		return nil, fmt.Errorf("state and code are required")
	}
	pendingMu.Lock()
	p := pending[state]
	delete(pending, state)
	pendingMu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("unknown or expired state")
	}
	if time.Now().After(p.expiresAt) {
		return nil, fmt.Errorf("authorize session expired")
	}
	if p.cfg.TokenURL == "" {
		return nil, fmt.Errorf("token_url is required for authorization code exchange")
	}
	fields := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  p.cfg.RedirectURI,
		"client_id":     p.cfg.ClientID,
		"code_verifier": p.verifier,
		"state":         state,
	}
	return tokenRequest(p.cfg, fields)
}

func refreshAuthCode(cfg authConfig, refreshToken string) (*tokenResponse, error) {
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("token_url is required for refresh")
	}
	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh token")
	}
	fields := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     cfg.ClientID,
	}
	if scopes := strings.TrimSpace(cfg.Scopes); scopes != "" {
		fields["scope"] = scopes
	}
	return tokenRequest(cfg, fields)
}

// ---------------------------------------------------------------------------
// device flow + token persistence (RFC 8628)

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type tokenError struct {
	Error string `json:"error"`
}

type storedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Server       string    `json:"server"`
	ClientID     string    `json:"client_id"`
	AccountID    string    `json:"account_id,omitempty"`
	Email        string    `json:"email,omitempty"`
}

// manager owns the token state for one provider.
type manager struct {
	provider string
	cfg      authConfig

	mu               sync.RWMutex
	token            *storedToken
	tokenFileModTime time.Time
}

func tokenFilePath(provider string) string {
	return filepath.Join(tokenDataDir, "oauth_"+safeTokenName(provider)+".json")
}

func newManager(provider string, cfg authConfig) *manager {
	m := &manager{provider: provider, cfg: cfg}
	m.loadToken()
	return m
}

func (m *manager) loadToken() {
	path := tokenFilePath(m.provider)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var t storedToken
	if err := json.Unmarshal(data, &t); err != nil {
		return
	}
	m.token = &t
	if info, err := os.Stat(path); err == nil {
		m.tokenFileModTime = info.ModTime()
	}
}

func (m *manager) tryReloadToken() bool {
	path := tokenFilePath(m.provider)
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.ModTime().After(m.tokenFileModTime) {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var t storedToken
	if err := json.Unmarshal(data, &t); err != nil {
		return false
	}
	m.token = &t
	m.tokenFileModTime = info.ModTime()
	return true
}

func (m *manager) saveToken() error {
	if err := os.MkdirAll(tokenDataDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.token, "", "  ")
	if err != nil {
		return err
	}
	path := tokenFilePath(m.provider)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil {
		m.tokenFileModTime = info.ModTime()
	}
	return nil
}

func (m *manager) hasToken() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tryReloadToken()
	return m.token != nil && m.token.AccessToken != ""
}

func (m *manager) tokenInfo() *storedToken {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tryReloadToken()
	if m.token == nil {
		return nil
	}
	cp := *m.token
	return &cp
}

func (m *manager) startDeviceFlow() (*deviceCodeResponse, error) {
	if m.cfg.Server == "" {
		return nil, fmt.Errorf("device flow requires an auth server (extension auth block)")
	}
	body, _ := json.Marshal(map[string]string{"client_id": m.cfg.ClientID})
	req, err := http.NewRequest("POST", m.cfg.Server+"/auth/device/code", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	m.cfg.applyUA(req)
	resp, err := m.cfg.httpc().Do(req)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device code request returned HTTP %d: %s", resp.StatusCode, string(b))
	}
	var dc deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	return &dc, nil
}

// exchangeDevice attempts one device_code exchange. pending reports
// authorization_pending / slow_down without treating them as failures.
func (m *manager) exchangeDevice(deviceCode string) (*tokenResponse, string, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode,
		"client_id":   m.cfg.ClientID,
	})
	req, err := http.NewRequest("POST", m.cfg.Server+"/auth/device/token", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	m.cfg.applyUA(req)
	resp, err := m.cfg.httpc().Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		var tok tokenResponse
		if err := json.Unmarshal(b, &tok); err != nil {
			return nil, "", fmt.Errorf("decode token response: %w", err)
		}
		return &tok, "", nil
	}
	var terr tokenError
	if err := json.Unmarshal(b, &terr); err != nil {
		return nil, "", fmt.Errorf("decode token error: %w", err)
	}
	switch terr.Error {
	case "authorization_pending":
		return nil, "authorization_pending", nil
	case "slow_down":
		return nil, "slow_down", nil
	case "expired_token":
		return nil, "", fmt.Errorf("device code expired, user must re-authorize")
	case "access_denied", "authorization_denied":
		return nil, "", fmt.Errorf("authorization denied by user")
	default:
		return nil, "", fmt.Errorf("token error: %s", terr.Error)
	}
}

func (m *manager) pollDevice(deviceCode string, interval time.Duration, expiresAt time.Time) (*tokenResponse, error) {
	for {
		if time.Now().After(expiresAt) {
			return nil, fmt.Errorf("device code expired")
		}
		time.Sleep(interval)
		tok, pending, err := m.exchangeDevice(deviceCode)
		if err != nil {
			return nil, err
		}
		if tok != nil {
			return tok, nil
		}
		if pending == "slow_down" {
			interval += 5 * time.Second
		}
	}
}

func (m *manager) refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token == nil || m.token.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}
	if m.cfg.TokenURL != "" {
		tok, err := refreshAuthCode(m.cfg, m.token.RefreshToken)
		if err != nil {
			return err
		}
		m.token.AccessToken = tok.AccessToken
		if tok.RefreshToken != "" {
			m.token.RefreshToken = tok.RefreshToken
		}
		m.token.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		return m.saveToken()
	}
	if m.cfg.Server == "" {
		return fmt.Errorf("no refresh endpoint configured")
	}
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": m.token.RefreshToken,
		"client_id":     m.cfg.ClientID,
	})
	req, err := http.NewRequest("POST", m.cfg.Server+"/auth/device/token", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	m.cfg.applyUA(req)
	resp, err := m.cfg.httpc().Do(req)
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("refresh returned HTTP %d: %s", resp.StatusCode, string(b))
	}
	var tok tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("decode refresh response: %w", err)
	}
	m.token.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		m.token.RefreshToken = tok.RefreshToken
	}
	m.token.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return m.saveToken()
}

func (m *manager) ensureFresh() error {
	m.mu.RLock()
	if m.token == nil {
		m.mu.RUnlock()
		return nil
	}
	if time.Now().Add(refreshSkew).Before(m.token.ExpiresAt) {
		m.mu.RUnlock()
		return nil
	}
	m.mu.RUnlock()
	return m.refresh()
}

func (m *manager) saveFromResponse(tok *tokenResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = &storedToken{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
		Server:       m.cfg.Server,
		ClientID:     m.cfg.ClientID,
	}
	if m.cfg.Server != "" {
		if info := m.fetchAccountInfo(tok.AccessToken); info != nil {
			m.token.AccountID = info.AccountID
			m.token.Email = info.Email
		}
	}
	return m.saveToken()
}

func (m *manager) clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = nil
	path := tokenFilePath(m.provider)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// fetchAccountInfo is best-effort metadata (email / account id).
func (m *manager) fetchAccountInfo(accessToken string) *storedToken {
	type userResponse struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	type orgResponse struct {
		ID string `json:"id"`
	}
	fetch := func(u string, out any) bool {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		m.cfg.applyUA(req)
		resp, err := m.cfg.httpc().Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		return json.NewDecoder(resp.Body).Decode(out) == nil
	}
	var user userResponse
	var orgs []orgResponse
	fetch(m.cfg.Server+"/api/user", &user)
	fetch(m.cfg.Server+"/api/orgs", &orgs)
	info := &storedToken{}
	if user.ID != "" {
		info.AccountID = user.ID
	}
	if user.Email != "" {
		info.Email = user.Email
	}
	if len(orgs) > 0 && info.AccountID == "" {
		info.AccountID = orgs[0].ID
	}
	if info.AccountID == "" && info.Email == "" {
		return nil
	}
	return info
}

// managerFor resolves the manager for a provider this addon owns.
func managerFor(payload map[string]any) (*manager, string, bool) {
	provider := str(payload["provider"])
	if provider == "" {
		return nil, "", false
	}
	if _, ok := providerOwned(provider); !ok {
		return nil, provider, false
	}
	cfg, ok := loadAuth()
	if !ok {
		return nil, provider, false
	}
	return newManager(provider, cfg), provider, true
}

func verificationBaseFor(cfg authConfig, uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	base := trimSlash(cfg.VerificationBase)
	if base == "" {
		return uri
	}
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return base + uri
}

func statusResp(m *manager, provider string) map[string]any {
	out := map[string]any{"has_token": false, "expired": false, "provider_name": provider}
	if info := m.tokenInfo(); info != nil {
		out["has_token"] = true
		out["expired"] = time.Now().After(info.ExpiresAt)
		out["expires_at"] = info.ExpiresAt
		if info.Email != "" {
			out["email"] = info.Email
		}
		if info.AccountID != "" {
			out["account_id"] = info.AccountID
		}
		if info.Server != "" {
			out["server"] = info.Server
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// addon API — every method takes one JSON string and returns one JSON string

// Start begins the device authorization flow for the provider.
func Start(payload string) string {
	in, _ := inMap(payload)
	m, provider, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	dc, err := m.startDeviceFlow()
	if err != nil {
		return errResp("failed to start device flow: %v", err)
	}
	interval := dc.Interval
	if interval <= 0 {
		interval = 5
	}
	expiresIn := dc.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 600
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)
	go func() {
		tok, err := m.pollDevice(dc.DeviceCode, time.Duration(interval)*time.Second, expiresAt)
		if err != nil {
			fmt.Printf("external auth: background polling stopped provider=%s error=%v\n", provider, err)
			return
		}
		if err := m.saveFromResponse(tok); err != nil {
			fmt.Printf("external auth: failed to save token provider=%s error=%v\n", provider, err)
			return
		}
		fmt.Printf("external auth: token saved provider=%s\n", provider)
	}()
	return objJSON(map[string]any{
		"user_code":                 dc.UserCode,
		"verification_uri_complete": verificationBaseFor(m.cfg, dc.VerificationURIComplete),
		"verification_base":         trimSlash(m.cfg.VerificationBase),
		"expires_in":                expiresIn,
		"interval":                  interval,
	})
}

// Poll performs one device-code exchange (manual polling).
func Poll(payload string) string {
	in, _ := inMap(payload)
	m, _, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	deviceCode := str(in["device_code"])
	if deviceCode == "" {
		return errResp("device_code is required")
	}
	intervalSec := 5
	if v, ok := in["interval"].(float64); ok && int(v) > 0 {
		intervalSec = int(v)
	}
	expiresIn := 600
	if v, ok := in["expires_in"].(float64); ok && int(v) > 0 {
		expiresIn = int(v)
	}
	interval := time.Duration(intervalSec) * time.Second
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)
	if time.Now().After(expiresAt) {
		return objJSON(map[string]any{"status": "error", "error": "device code expired"})
	}
	time.Sleep(interval)
	tok, _, err := m.exchangeDevice(deviceCode)
	if err != nil {
		return objJSON(map[string]any{"status": "error", "error": err.Error()})
	}
	if tok == nil {
		return objJSON(map[string]any{"status": "pending"})
	}
	if err := m.saveFromResponse(tok); err != nil {
		return errResp("failed to save token: %v", err)
	}
	return objJSON(map[string]any{"status": "authorized", "access_token": tok.AccessToken})
}

// TokenStatus reports the stored token state for the provider.
func TokenStatus(payload string) string {
	in, _ := inMap(payload)
	m, provider, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	return objJSON(statusResp(m, provider))
}

// Refresh forces a token refresh for the provider.
func Refresh(payload string) string {
	in, _ := inMap(payload)
	m, provider, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	if !m.hasToken() {
		return errResp("no token stored for provider")
	}
	if err := m.refresh(); err != nil {
		return errResp("failed to refresh token: %v", err)
	}
	return objJSON(statusResp(m, provider))
}

// RefreshAll refreshes every stored token this addon owns.
func RefreshAll(payload string) string {
	results := make([]map[string]any, 0)
	for _, rec := range ownedProviders() {
		name := str(rec["name"])
		cfg, ok := loadAuth()
		if !ok {
			continue
		}
		m := newManager(name, cfg)
		if !m.hasToken() {
			continue
		}
		if err := m.refresh(); err != nil {
			results = append(results, map[string]any{"name": name, "error": err.Error()})
			continue
		}
		results = append(results, map[string]any{"name": name, "refreshed": true})
	}
	return objJSON(results)
}

// ClearToken deletes the stored token for the provider.
func ClearToken(payload string) string {
	in, _ := inMap(payload)
	m, _, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	if err := m.clear(); err != nil {
		return errResp("failed to clear token: %v", err)
	}
	return objJSON(map[string]any{"status": "cleared"})
}

// FlowInfo reports the active grant for the provider.
func FlowInfo(payload string) string {
	in, _ := inMap(payload)
	provider := str(in["provider"])
	m, _, ok := managerFor(in)
	if !ok {
		return skipResp(provider)
	}
	cfg := m.cfg
	grant := cfg.Grant
	if grant == "" {
		grant = "device"
	}
	hasAuthCode := cfg.Grant == "authorization_code" || cfg.TokenURL != ""
	return objJSON(map[string]any{
		"provider":           provider,
		"grant":              grant,
		"has_token":          m.hasToken(),
		"authorization_code": hasAuthCode,
	})
}

// StartAuthorize creates a PKCE session and returns the authorize URL.
func StartAuthorize(payload string) string {
	in, _ := inMap(payload)
	m, _, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	cfg := m.cfg
	if v := str(in["redirect_uri"]); v != "" {
		cfg.RedirectURI = v
	}
	if v := str(in["scope"]); v != "" {
		cfg.Scopes = v
	}
	out, err := authCodeStart(cfg)
	if err != nil {
		return errResp("%v", err)
	}
	return objJSON(out)
}

// CompleteAuthorize exchanges a pasted/redirected authorization code.
func CompleteAuthorize(payload string) string {
	in, _ := inMap(payload)
	m, _, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	code, state := str(in["code"]), str(in["state"])
	if code == "" || state == "" {
		code, state = splitCodeState(str(in["code_and_state"]))
	}
	if (code == "" || state == "") && str(in["url"]) != "" {
		code, state = parseCallbackURL(str(in["url"]))
	}
	if code == "" || state == "" {
		return errResp("code and state are required (or code_and_state / url)")
	}
	tok, err := authCodeComplete(state, code)
	if err != nil {
		return errResp("%v", err)
	}
	if err := m.saveFromResponse(tok); err != nil {
		return errResp("failed to save token: %v", err)
	}
	return objJSON(map[string]any{"status": "authorized", "access_token": tok.AccessToken})
}

// Providers lists every provider this addon owns with its token status.
func Providers(payload string) string {
	out := make([]map[string]any, 0)
	cfg, ok := loadAuth()
	if !ok {
		return objJSON(out)
	}
	for _, rec := range ownedProviders() {
		name := str(rec["name"])
		m := newManager(name, cfg)
		st := statusResp(m, name)
		item := map[string]any{
			"name":      name,
			"has_token": st["has_token"],
			"expired":   st["expired"],
		}
		if v, exists := st["email"]; exists {
			item["email"] = v
		}
		if v, exists := st["account_id"]; exists {
			item["account_id"] = v
		}
		out = append(out, item)
	}
	return objJSON(out)
}

// Token returns a ready-to-use bearer token for upstream requests.
func Token(payload string) string {
	in, _ := inMap(payload)
	m, _, ok := managerFor(in)
	if !ok {
		return skipResp(str(in["provider"]))
	}
	if !m.hasToken() {
		return errResp("no token stored")
	}
	if err := m.ensureFresh(); err != nil {
		return errResp("token refresh failed: %v", err)
	}
	info := m.tokenInfo()
	if info == nil || info.AccessToken == "" {
		return errResp("no token stored")
	}
	return objJSON(map[string]any{"token": info.AccessToken})
}

// ---------------------------------------------------------------------------
// helpers for manual callback parsing

func splitCodeState(s string) (code, state string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	parts := strings.SplitN(s, "#", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return "", ""
}

func parseCallbackURL(raw string) (code, state string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", ""
	}
	q := u.Query()
	code = strings.TrimSpace(q.Get("code"))
	state = strings.TrimSpace(q.Get("state"))
	if code == "" || state == "" {
		if frag := u.Fragment; frag != "" {
			if c, st := splitCodeState(frag); c != "" {
				return c, st
			}
			fq, err := url.ParseQuery(frag)
			if err == nil {
				if code == "" {
					code = strings.TrimSpace(fq.Get("code"))
				}
				if state == "" {
					state = strings.TrimSpace(fq.Get("state"))
				}
			}
		}
	}
	return code, state
}
