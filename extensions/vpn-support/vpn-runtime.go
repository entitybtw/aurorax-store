// addon-kind: runtime
package main

// VPN support runtime addon.
//
// Reads subscriptions you list, parses them, probes every endpoint, keeps the
// best ones (count, latency threshold, sort order) and drops the ones that
// stopped answering. Where the endpoints sit relative to the source addresses
// configured on the provider is up to egress_mode: rotate them together (the
// default), keep them as the fallback tier, or prefer them exclusively.
//
// Everything here runs on the gateway's stdlib only — no external packages.
// Network work happens on a background goroutine so a pick never blocks a
// request.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	stateFile       = "vpn-support-state.json"
	minRefreshGap   = 30 * time.Second
	fetchTimeout    = 30 * time.Second
	switchTimeout   = 10 * time.Second
	maxSubBodyBytes = 8 << 20
	probeWorkers    = 16
)

// Endpoint is one remote exit discovered from a subscription.
type Endpoint struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Region   string `json:"region"`
	Latency  int    `json:"latency_ms"`
	Alive    bool   `json:"alive"`
}

// State is persisted next to the addon so it survives reloads.
type State struct {
	LastRefresh time.Time  `json:"last_refresh"`
	Endpoints   []Endpoint `json:"endpoints"`
	// Selected are the display names of the kept endpoints, in the order the
	// exits use them. SelectedKeys carries the matching identities
	// (protocol|host|port) so two endpoints sharing one label stay two
	// endpoints — subscriptions repeat labels freely and the gateway keys
	// exit health by name.
	Selected      []string `json:"selected"`
	SelectedKeys  []string `json:"selected_keys"`
	Errors        []string `json:"errors"`
	Subscriptions int      `json:"subscriptions"`
	Fetched       int      `json:"fetched"`
	CoreSwitch    string   `json:"core_switch"`
	SettingsFP    string   `json:"settings_fp"`
}

// endpointKey is the identity of an endpoint: protocol + address. Used for
// deduplication, to mark exactly the endpoints that were kept, and to build
// the address part of an exit name.
func endpointKey(e Endpoint) string {
	return strings.ToLower(e.Protocol) + "|" + strings.ToLower(strings.TrimSpace(e.Host)) + "|" + strconv.Itoa(e.Port)
}

// endpointAddress turns an endpointKey back into the address shown to the
// operator: "vless|host|443" -> "host:443".
func endpointAddress(key string) string {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return ""
	}
	return parts[1] + ":" + parts[2]
}

var (
	mu         sync.Mutex
	st         State
	loadedFrom string
	refreshing bool
)

// payload mirrors the JSON the gateway hands every hook.
type payload struct {
	Hook      string            `json:"hook"`
	Extension string            `json:"extension"`
	Provider  string            `json:"provider"`
	Key       string            `json:"key"`
	Dir       string            `json:"dir"`
	Settings  map[string]string `json:"settings"`
	Config    map[string]string `json:"config"`
}

func parsePayload(raw string) payload {
	var p payload
	_ = json.Unmarshal([]byte(raw), &p)
	return p
}

// val resolves a setting: the operator's saved value wins over the shipped
// default, and def applies when neither is set.
func val(p payload, key, def string) string {
	if v, ok := p.Config[key]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := p.Settings[key]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func toInt(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// splitList accepts comma, semicolon or newline separated values and also a
// JSON-looking array, so a pasted list always works.
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

func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// appliesTo implements the comma-separated target list: this extension only
// contributes exits to the providers/pools it names ("zen, backup", "*" or
// "zen-*").
func appliesTo(p payload) bool {
	patterns := splitList(val(p, "apply_to", "*"))
	if len(patterns) == 0 {
		return true
	}
	target := strings.TrimSpace(p.Provider)
	if target == "" {
		return true
	}
	for _, pat := range patterns {
		if pat == "*" {
			return true
		}
		if strings.EqualFold(pat, target) {
			return true
		}
		if strings.HasSuffix(pat, "*") &&
			strings.HasPrefix(strings.ToLower(target), strings.ToLower(strings.TrimSuffix(pat, "*"))) {
			return true
		}
	}
	return false
}

func statePath(dir string) string {
	return filepath.Join(dir, stateFile)
}

// loadState reads the persisted state once per directory.
func loadState(dir string) {
	if dir == "" {
		return
	}
	mu.Lock()
	if loadedFrom == dir {
		mu.Unlock()
		return
	}
	mu.Unlock()

	data, err := os.ReadFile(statePath(dir))
	var next State
	if err == nil {
		_ = json.Unmarshal(data, &next)
	}
	mu.Lock()
	if loadedFrom != dir {
		st = next
		loadedFrom = dir
	}
	mu.Unlock()
}

func saveStateLocked(dir string) {
	if dir == "" {
		return
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(statePath(dir), data, 0o600)
}

// OnInit is called when the addon is loaded.
func OnInit(raw string) string {
	p := parsePayload(raw)
	loadState(p.Dir)
	mu.Lock()
	defer mu.Unlock()
	return fmt.Sprintf(`{"ok":true,"endpoints":%d,"selected":%d,"refreshed":%s}`,
		len(st.Endpoints), len(st.Selected), quote(st.LastRefresh.Format(time.RFC3339)))
}

// OnSettingsSave runs after the operator changes this extension's settings:
// force a re-fetch on the next pick instead of waiting out the interval.
func OnSettingsSave(raw string) string {
	p := parsePayload(raw)
	loadState(p.Dir)
	mu.Lock()
	st.LastRefresh = time.Time{}
	dir := loadedFrom
	mu.Unlock()
	maybeStartRefresh(p, dir)
	return `{"ok":true}`
}

// EgressCandidates answers the gateway's exit picker with the endpoints this
// extension contributes for the provider being asked about.
func EgressCandidates(raw string) string {
	p := parsePayload(raw)
	if !appliesTo(p) {
		return `{"candidates":[]}`
	}
	loadState(p.Dir)
	maybeStartRefresh(p, p.Dir)

	// No local tunnel implied: report-only mode contributes no exits.
	if val(p, "core_kind", "none") == "none" {
		return `{"candidates":[]}`
	}

	mu.Lock()
	selected := append([]string(nil), st.Selected...)
	selectedKeys := append([]string(nil), st.SelectedKeys...)
	mu.Unlock()

	if len(selected) == 0 {
		return `{"candidates":[]}`
	}

	tier := egressTier(p)
	ports := splitList(val(p, "local_socks_ports", "1080"))
	if len(ports) == 0 {
		ports = []string{"1080"}
	}

	// One exit per selected node: the operator asks for N endpoints and gets
	// N, and the local ports are simply reused round-robin behind them. The
	// address rides in the name because the gateway keys exit health by name
	// and subscriptions reuse display labels across different addresses; a
	// label+address that still repeats falls back to the full identity.
	var b strings.Builder
	seen := make(map[string]bool, len(selected))
	b.WriteString(`{"candidates":[`)
	for i, node := range selected {
		if i > 0 {
			b.WriteString(",")
		}
		port := strings.TrimSpace(ports[i%len(ports)])
		label := "vpn:" + node
		if i < len(selectedKeys) && selectedKeys[i] != "" {
			if addr := endpointAddress(selectedKeys[i]); addr != "" {
				label = "vpn:" + node + " @ " + addr
				if seen[label] {
					label = "vpn:" + node + " @ " + selectedKeys[i]
				}
			}
		}
		seen[label] = true
		b.WriteString(`{"name":`)
		b.WriteString(quote(label))
		b.WriteString(`,"proxy":`)
		b.WriteString(quote("socks5://127.0.0.1:" + port))
		b.WriteString(`,"tier":`)
		b.WriteString(strconv.Itoa(tier))
		b.WriteString(`}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

// egressTier maps this extension's egress_mode onto the gateway's exit tiers:
//
//	rotate    (default) — tier 0: these endpoints and the provider's own
//	                      source addresses form one rotation and are picked
//	                      from together.
//	fallback  — tier 1: the endpoints take over once the provider's own
//	                      source addresses fail or get rate-limited.
//	vpn_only  — tier -1: the endpoints are preferred and the provider's own
//	                      source addresses are the last resort.
//
// An unrecognised value behaves like the default so a typo never silently
// disables the exits.
func egressTier(p payload) int {
	switch strings.TrimSpace(val(p, "egress_mode", "rotate")) {
	case "fallback":
		return 1
	case "vpn_only":
		return -1
	default:
		return 0
	}
}

// fetchSettings are the keys whose value changes what a refresh fetches and
// keeps. Everything else (exit mode, core, target list) only affects how the
// already fetched set is used, so it does not invalidate the last refresh.
var fetchSettings = []string{
	"subscriptions",
	"subscription_headers",
	"subscription_base_url",
	"node_count",
	"node_order",
	"quality_max_ms",
	"probe_count",
	"probe_timeout_ms",
	"protocols",
	"region_include",
	"region_exclude",
}

// settingsFP fingerprints the fetch-relevant settings. The gateway never calls
// this addon's OnSettingsSave hook, so without this the operator would wait
// out the whole refresh interval after editing a subscription.
func settingsFP(p payload) string {
	var b strings.Builder
	for _, key := range fetchSettings {
		b.WriteString(key)
		b.WriteByte(0)
		b.WriteString(val(p, key, ""))
		b.WriteByte(0x1f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("%x", sum[:8])
}

// maybeStartRefresh kicks off a background refresh when one is due. The pick
// path never waits for it.
func maybeStartRefresh(p payload, dir string) {
	if dir == "" {
		return
	}
	interval := toInt(val(p, "refresh_interval_minutes", "30"), 30)
	fp := settingsFP(p)

	mu.Lock()
	changed := st.SettingsFP != fp
	never := st.LastRefresh.IsZero()
	due := never || changed || (interval > 0 && time.Since(st.LastRefresh) >= time.Duration(interval)*time.Minute)
	// A gap guard keeps a tiny interval from spinning the fetcher when the
	// operator saves settings repeatedly. An edited setting is the operator
	// asking for fresh data, so it bypasses the guard.
	tooSoon := !never && !changed && time.Since(st.LastRefresh) < minRefreshGap
	if !due || refreshing || tooSoon {
		mu.Unlock()
		return
	}
	refreshing = true
	mu.Unlock()

	go func() {
		defer func() {
			mu.Lock()
			refreshing = false
			mu.Unlock()
		}()
		runRefresh(p, dir)
	}()
}

// runRefresh fetches, parses, probes, filters and stores the endpoint set.
func runRefresh(p payload, dir string) {
	endpoints, errs, subs, fetched := collect(p)

	// The raw list repeats entries across subscriptions and even inside one;
	// keep a single row per distinct endpoint so the status, the IP list and
	// the "selected" flag count endpoints rather than repetitions.
	endpoints = dedupeEndpoints(endpoints)

	timeoutMS := toInt(val(p, "probe_timeout_ms", "1500"), 1500)
	samples := toInt(val(p, "probe_count", "3"), 3)
	if samples < 1 {
		samples = 1
	}
	probeAll(endpoints, timeoutMS, samples)

	filtered, filterErrs := filterEndpoints(p, endpoints)
	errs = append(errs, filterErrs...)

	// Subscriptions repeat the same node under several names; keeping two
	// entries for one host:port would burn a slot of node_count on a
	// duplicate and later collapse into a single exit anyway.
	filtered = dedupeEndpoints(filtered)

	keep := toInt(val(p, "node_count", "3"), 3)
	picked := pickEndpoints(filtered, keep)

	selected := make([]string, 0, len(picked))
	selectedKeys := make([]string, 0, len(picked))
	for _, e := range picked {
		selected = append(selected, e.Name)
		selectedKeys = append(selectedKeys, endpointKey(e))
	}

	coreSwitch := ""
	if len(selected) > 0 {
		coreSwitch = switchCore(p, selected[0])
		if coreSwitch != "" {
			errs = append(errs, coreSwitch)
		}
	}

	mu.Lock()
	st = State{
		LastRefresh:   time.Now(),
		Endpoints:     endpoints,
		Selected:      selected,
		SelectedKeys:  selectedKeys,
		Errors:        trimErrors(errs),
		Subscriptions: subs,
		Fetched:       fetched,
		CoreSwitch:    coreSwitch,
		SettingsFP:    settingsFP(p),
	}
	saveStateLocked(dir)
	mu.Unlock()
}

// pickEndpoints keeps up to limit endpoints, labels first: a subscription may
// hand out the same display name for two different addresses, and a repeat
// would otherwise waste a slot (and collapse into one exit, because the
// gateway keys exits by name). When labels run out before the count, the
// remaining slots are filled by address, which is already unique here.
func pickEndpoints(pool []Endpoint, limit int) []Endpoint {
	if limit <= 0 {
		return pool
	}
	out := make([]Endpoint, 0, limit)
	seenLabel := make(map[string]bool, len(pool))
	for _, e := range pool {
		if len(out) >= limit {
			break
		}
		if seenLabel[e.Name] {
			continue
		}
		seenLabel[e.Name] = true
		out = append(out, e)
	}
	if len(out) >= limit {
		return out
	}
	seenKey := make(map[string]bool, len(out))
	for _, e := range out {
		seenKey[endpointKey(e)] = true
	}
	for _, e := range pool {
		if len(out) >= limit {
			break
		}
		key := endpointKey(e)
		if seenKey[key] {
			continue
		}
		seenKey[key] = true
		out = append(out, e)
	}
	return out
}

func trimErrors(in []string) []string {
	var out []string
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e != "" {
			out = append(out, e)
		}
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// collect fetches every configured subscription and parses the URIs.
//
// An entry does not have to be a URL: a node URI pasted straight into the
// list (vless://, vmess://, ss://, trojan://) is parsed as-is, and a bare
// token is joined with subscription_base_url when that is set. Anything else
// is reported as an error rather than skipped in silence.
func collect(p payload) ([]Endpoint, []string, int, int) {
	entries := splitList(val(p, "subscriptions", ""))
	base := strings.TrimSpace(val(p, "subscription_base_url", ""))
	var errs []string
	var out []Endpoint
	fetched := 0

	headerRaw := val(p, "subscription_headers", "")
	headers := map[string]string{}
	if strings.TrimSpace(headerRaw) != "" {
		var parsed map[string]string
		if err := json.Unmarshal([]byte(headerRaw), &parsed); err != nil {
			errs = append(errs, "subscription_headers is not a JSON object: "+err.Error())
		} else {
			for k, v := range parsed {
				headers[k] = v
			}
		}
	}

	for _, entry := range entries {
		target := entry
		if !isSubscriptionURL(target) {
			if ep, ok := parseURI(target); ok {
				out = append(out, ep)
				fetched++
				continue
			}
			resolved, ok := joinSubscriptionBase(target, base)
			if !ok {
				errs = append(errs, entry+": not an http(s) subscription URL or a supported node URI")
				continue
			}
			target = resolved
		}
		body, err := fetchSubscription(target, headers)
		if err != nil {
			errs = append(errs, target+": "+err.Error())
			continue
		}
		fetched++
		for _, line := range subscriptionLines(body) {
			ep, ok := parseURI(line)
			if !ok {
				continue
			}
			out = append(out, ep)
		}
	}
	// Yaegi miscompiles `len()` used directly as one argument of a
	// multi-value return (the destination slot ends up holding the slice),
	// so the length is computed into a named int first.
	count := len(entries)
	return out, errs, count, fetched
}

// isSubscriptionURL reports whether the entry is fetched over http(s).
func isSubscriptionURL(entry string) bool {
	l := strings.ToLower(strings.TrimSpace(entry))
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// joinSubscriptionBase combines a bare token with the configured base URL.
// base is expected to point at the collection endpoint, so the token becomes
// the last path segment: https://host/sub/ + abc123.
func joinSubscriptionBase(entry, base string) (string, bool) {
	if base == "" || strings.TrimSpace(entry) == "" {
		return "", false
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(entry, "/"), true
}

func fetchSubscription(rawURL string, headers map[string]string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "aurora-vpn-support/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: fetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSubBodyBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// subscriptionLines handles both plain URI lists and base64-wrapped payloads.
func subscriptionLines(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	if !strings.Contains(body, "://") {
		if dec, ok := tryBase64(body); ok {
			if strings.Contains(string(dec), "://") {
				body = string(dec)
			}
		}
	}
	return splitListLines(body)
}

func splitListLines(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func tryBase64(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// parseURI understands vless, vmess, shadowsocks and trojan share links.
func parseURI(raw string) (Endpoint, bool) {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "vless://"), strings.HasPrefix(lower, "trojan://"):
		return parseAuthorityURI(raw)
	case strings.HasPrefix(lower, "vmess://"):
		return parseVMess(raw)
	case strings.HasPrefix(lower, "ss://"):
		return parseShadowsocks(raw)
	}
	return Endpoint{}, false
}

func parseAuthorityURI(raw string) (Endpoint, bool) {
	protocol := "vless"
	if strings.HasPrefix(strings.ToLower(raw), "trojan://") {
		protocol = "trojan"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, false
	}
	host := u.Hostname()
	if host == "" {
		return Endpoint{}, false
	}
	port := 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	name := strings.TrimSpace(u.Fragment)
	if name == "" {
		name = host
	}
	return Endpoint{
		ID:       protocol + "://" + host + ":" + strconv.Itoa(port),
		Name:     name,
		Protocol: protocol,
		Host:     host,
		Port:     port,
		Region:   regionOf(name),
	}, true
}

func parseVMess(raw string) (Endpoint, bool) {
	payload := strings.TrimSpace(strings.TrimPrefix(raw, "vmess://"))
	dec, ok := tryBase64(payload)
	if !ok {
		return Endpoint{}, false
	}
	var obj map[string]any
	if err := json.Unmarshal(dec, &obj); err != nil {
		return Endpoint{}, false
	}
	host := strings.TrimSpace(asString(obj["add"]))
	if host == "" {
		return Endpoint{}, false
	}
	port := 443
	if n, ok := asInt(obj["port"]); ok {
		port = n
	}
	name := strings.TrimSpace(asString(obj["ps"]))
	if name == "" {
		name = host
	}
	return Endpoint{
		ID:       "vmess://" + host + ":" + strconv.Itoa(port),
		Name:     name,
		Protocol: "vmess",
		Host:     host,
		Port:     port,
		Region:   regionOf(name),
	}, true
}

func parseShadowsocks(raw string) (Endpoint, bool) {
	rest := strings.TrimPrefix(raw, "ss://")
	fragment := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		fragment = unescape(rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.Index(rest, "@"); i >= 0 {
		// ss://<userinfo>@host:port — userinfo is base64(method:password).
		authority := rest[i+1:]
		host, port := splitHostPort(authority, 8388)
		if host == "" {
			return Endpoint{}, false
		}
		return ssResult(host, port, fragment), true
	}
	// ss://<base64(method:password@host:port)>
	dec, ok := tryBase64(rest)
	if !ok {
		return Endpoint{}, false
	}
	inner := string(dec)
	at := strings.LastIndex(inner, "@")
	if at < 0 {
		return Endpoint{}, false
	}
	host, port := splitHostPort(inner[at+1:], 8388)
	if host == "" {
		return Endpoint{}, false
	}
	return ssResult(host, port, fragment), true
}

func ssResult(host string, port int, fragment string) Endpoint {
	name := strings.TrimSpace(fragment)
	if name == "" {
		name = host
	}
	return Endpoint{
		ID:       "ss://" + host + ":" + strconv.Itoa(port),
		Name:     name,
		Protocol: "ss",
		Host:     host,
		Port:     port,
		Region:   regionOf(name),
	}
}

func splitHostPort(authority string, defPort int) (string, int) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0
	}
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end < 0 {
			return "", 0
		}
		host := authority[1:end]
		port := defPort
		if rest := authority[end+1:]; strings.HasPrefix(rest, ":") {
			if n, err := strconv.Atoi(rest[1:]); err == nil {
				port = n
			}
		}
		return host, port
	}
	host := authority
	port := defPort
	if i := strings.LastIndex(authority, ":"); i > 0 {
		host = authority[:i]
		if n, err := strconv.Atoi(authority[i+1:]); err == nil {
			port = n
		}
	}
	return strings.Trim(host, "[]"), port
}

func unescape(s string) string {
	if out, err := url.PathUnescape(s); err == nil {
		return out
	}
	return s
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.Itoa(int(t))
	case json.Number:
		return t.String()
	}
	return ""
}

func asInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n, true
		}
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return int(n), true
		}
	}
	return 0, false
}

// regionOf takes the leading token of a name ("DE Frankfurt 01" → "DE") so
// include/exclude filters can match on a country or city fragment.
func regionOf(name string) string {
	fields := strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})
	if len(fields) == 0 {
		return name
	}
	return fields[0]
}

// probeAll measures every endpoint concurrently; results land in place.
func probeAll(endpoints []Endpoint, timeoutMS, samples int) {
	if len(endpoints) == 0 {
		return
	}
	ch := make(chan int, len(endpoints))
	for i := range endpoints {
		ch <- i
	}
	close(ch)

	workers := probeWorkers
	if workers > len(endpoints) {
		workers = len(endpoints)
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				lat, ok := probeOne(endpoints[i].Host, endpoints[i].Port, timeoutMS, samples)
				endpoints[i].Latency = lat
				endpoints[i].Alive = ok
			}
		}()
	}
	wg.Wait()
}

func probeOne(host string, port, timeoutMS, samples int) (int, bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	var observed []int
	for i := 0; i < samples; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return 0, false
		}
		_ = conn.Close()
		observed = append(observed, int(time.Since(start)/time.Millisecond))
	}
	sort.Ints(observed)
	return observed[len(observed)/2], true
}

// filterEndpoints applies protocol, region and quality filters, then sorts.
// dedupeEndpoints drops repeated nodes, keeping the fastest probe of each
// identical protocol+host+port so one node is never counted twice.
func dedupeEndpoints(in []Endpoint) []Endpoint {
	seen := make(map[string]bool, len(in))
	out := make([]Endpoint, 0, len(in))
	for _, e := range in {
		key := endpointKey(e)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}

// filterEndpoints narrows the probed set to the operator's protocols, regions
// and quality bar, then orders it the way node_order asks.
func filterEndpoints(p payload, endpoints []Endpoint) ([]Endpoint, []string) {
	var errs []string
	allowed := map[string]bool{}
	for _, proto := range splitList(val(p, "protocols", "vless,vmess,ss,trojan")) {
		allowed[strings.ToLower(proto)] = true
	}
	include := splitList(val(p, "region_include", ""))
	exclude := splitList(val(p, "region_exclude", ""))
	quality := toInt(val(p, "quality_max_ms", "0"), 0)
	order := strings.ToLower(val(p, "node_order", "best_first"))

	kept := make([]Endpoint, 0, len(endpoints))
	droppedDead := 0
	for _, e := range endpoints {
		if !e.Alive {
			droppedDead++
			continue
		}
		if len(allowed) > 0 && !allowed[strings.ToLower(e.Protocol)] {
			continue
		}
		if quality > 0 && e.Latency > quality {
			continue
		}
		if len(include) > 0 && !matchesAny(e, include) {
			continue
		}
		if len(exclude) > 0 && matchesAny(e, exclude) {
			continue
		}
		kept = append(kept, e)
	}
	if droppedDead > 0 {
		errs = append(errs, fmt.Sprintf("dropped %d endpoint(s) that stopped answering", droppedDead))
	}

	sort.SliceStable(kept, func(i, j int) bool {
		return kept[i].Latency < kept[j].Latency
	})
	switch order {
	case "worst_first":
		for l, r := 0, len(kept)-1; l < r; l, r = l+1, r-1 {
			kept[l], kept[r] = kept[r], kept[l]
		}
	case "random":
		// Deterministic shuffle-free jitter: rotate by the current second so
		// repeated refreshes do not always expose the same head.
		if len(kept) > 1 {
			off := int(time.Now().UnixNano() % int64(len(kept)))
			if off > 0 {
				rotated := make([]Endpoint, 0, len(kept))
				rotated = append(rotated, kept[off:]...)
				rotated = append(rotated, kept[:off]...)
				kept = rotated
			}
		}
	}
	return kept, errs
}

func matchesAny(e Endpoint, patterns []string) bool {
	hay := strings.ToLower(e.Name + " " + e.Region)
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if strings.HasSuffix(pat, "*") {
			if strings.Contains(hay, strings.TrimSuffix(pat, "*")) {
				return true
			}
			continue
		}
		if strings.Contains(hay, pat) {
			return true
		}
	}
	return false
}

// switchCore asks the tunnel core to move to another endpoint. Only cores
// exposing an HTTP control API are handled; "static" leaves that to the
// operator, who maps each local port to an endpoint.
func switchCore(p payload, node string) string {
	kind := strings.ToLower(val(p, "core_kind", "none"))
	if kind == "static" || kind == "none" {
		return ""
	}
	if kind != "singbox" {
		return "core_kind " + kind + " has no HTTP switch; use static local ports"
	}
	api := strings.TrimRight(val(p, "core_api_url", ""), "/")
	if api == "" {
		return "core_api_url is empty"
	}
	group := val(p, "core_group", "proxy")
	target := api + "/proxies/" + url.PathEscape(group)

	body, err := json.Marshal(map[string]string{"name": node})
	if err != nil {
		return err.Error()
	}
	req, err := http.NewRequest(http.MethodPut, target, strings.NewReader(string(body)))
	if err != nil {
		return err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := val(p, "core_api_token", ""); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	client := &http.Client{Timeout: switchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "core switch failed: " + err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Sprintf("core switch returned %s", resp.Status)
	}
	return ""
}

// Data answers the dashboard's live block/widget requests. The gateway calls
// it with the key named by a block's `source` field.
//
// Both `stats` (for a stats widget) and `blocks` (for page content) are
// returned together so the same key works in either place.
func Data(raw string) string {
	p := parsePayload(raw)
	loadState(p.Dir)
	maybeStartRefresh(p, p.Dir)

	mu.Lock()
	snapshot := st
	mu.Unlock()

	refreshed := "never"
	if !snapshot.LastRefresh.IsZero() {
		refreshed = snapshot.LastRefresh.Format("2006-01-02 15:04:05")
	}
	alive := 0
	for _, e := range snapshot.Endpoints {
		if e.Alive {
			alive++
		}
	}

	stats := []map[string]string{
		{"k": "Endpoints", "v": strconv.Itoa(len(snapshot.Endpoints))},
		{"k": "Answering", "v": strconv.Itoa(alive)},
		{"k": "Selected", "v": strconv.Itoa(len(snapshot.Selected))},
		{"k": "Subscriptions", "v": strconv.Itoa(snapshot.Subscriptions)},
	}

	kv := []map[string]string{
		{"k": "Last refresh", "v": refreshed},
		{"k": "Core switch", "v": orDash(snapshot.CoreSwitch)},
		{"k": "Applies to", "v": orDash(val(p, "apply_to", "*"))},
		{"k": "Rotation", "v": orDash(val(p, "egress_mode", "rotate"))},
		{"k": "Order", "v": orDash(val(p, "node_order", "best_first"))},
		{"k": "Keep", "v": orDash(val(p, "node_count", "3"))},
	}

	if strings.TrimSpace(p.Key) == "nodes" {
		return nodesPayload(snapshot, kv)
	}
	// Machine-readable endpoint list for the dashboard: a pool or a provider
	// shows which servers are bound to it straight from this payload, without
	// scraping the prose the "nodes" key renders for humans.
	if strings.TrimSpace(p.Key) == "servers" {
		return serversPayload(snapshot, p)
	}

	blocks := []any{
		map[string]any{"kind": "kv", "kv": kv},
	}
	if len(snapshot.Errors) > 0 {
		blocks = append(blocks, map[string]any{"kind": "divider"})
		blocks = append(blocks, map[string]any{"kind": "list", "items": snapshot.Errors})
	}
	return mustJSON(map[string]any{"stats": stats, "kv": kv, "blocks": blocks})
}

func nodesPayload(snapshot State, kv []map[string]string) string {
	if len(snapshot.Endpoints) == 0 {
		return mustJSON(map[string]any{
			"blocks": []any{
				map[string]any{"kind": "text", "text": "No endpoints yet — subscriptions are fetched in the background after the extension is applied."},
				map[string]any{"kind": "kv", "kv": kv},
			},
		})
	}
	items := make([]string, 0, len(snapshot.Endpoints))
	for _, e := range snapshot.Endpoints {
		mark := "x"
		if e.Alive {
			mark = "ok"
		}
		items = append(items, fmt.Sprintf(
			"%s  %s  %s:%d  %dms  [%s]", mark, e.Protocol, e.Host, e.Port, e.Latency, e.Name))
	}
	blocks := []any{
		map[string]any{"kind": "kv", "kv": kv},
		map[string]any{"kind": "list", "items": items},
	}
	if len(snapshot.Selected) > 0 {
		blocks = append(blocks, map[string]any{"kind": "divider"})
		blocks = append(blocks, map[string]any{
			"kind": "text",
			"text": "Selected: " + strings.Join(snapshot.Selected, ", "),
		})
	}
	return mustJSON(map[string]any{"blocks": blocks})
}

// serversPayload is the machine-readable endpoint list behind the dashboard's
// pool and provider views. Every endpoint is listed with the flags an operator
// needs to tell the kept ones from the rest: `selected` marks the endpoints
// that survived probing and trimming, `alive` whether the last probe answered.
// apply_to, egress_mode and core_kind ride along so the caller can match the
// list against the pool or provider it is rendering and say whether these
// servers are actually in the rotation.
func serversPayload(snapshot State, p payload) string {
	// Prefer addresses: labels repeat across a subscription, so marking by
	// name would light up every endpoint that shares one of the kept labels.
	// A state file written before the keys existed falls back to labels.
	byKey := make(map[string]bool, len(snapshot.SelectedKeys))
	for _, key := range snapshot.SelectedKeys {
		byKey[key] = true
	}
	byName := make(map[string]bool, len(snapshot.Selected))
	for _, name := range snapshot.Selected {
		byName[name] = true
	}
	useKeys := len(snapshot.SelectedKeys) > 0

	servers := make([]map[string]any, 0, len(snapshot.Endpoints))
	for _, e := range snapshot.Endpoints {
		selected := byName[e.Name]
		if useKeys {
			selected = byKey[endpointKey(e)]
		}
		servers = append(servers, map[string]any{
			"host":       e.Host,
			"port":       e.Port,
			"name":       e.Name,
			"protocol":   e.Protocol,
			"alive":      e.Alive,
			"latency_ms": e.Latency,
			"selected":   selected,
		})
	}
	return mustJSON(map[string]any{
		"apply_to":    val(p, "apply_to", "*"),
		"egress_mode": val(p, "egress_mode", "rotate"),
		"core_kind":   val(p, "core_kind", "none"),
		"servers":     servers,
	})
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"encode failed"}`
	}
	return string(b)
}
