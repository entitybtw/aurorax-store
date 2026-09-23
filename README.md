# AuroraX Store

**Gateway community extension repo** for Aurora.

This is a **plain static repo**: throw extension JSON files into `extensions/`.
The page and API only expose **info + raw content** — no multi-repo UI here.
Repo base URLs are managed in **Aurora → Settings → Extensions**.

---

## ⚠️ Community extensions — be careful

Everything listed here is **added by the community**. There is **no review guarantee**.

- Extensions can **change gateway behavior**: headers, tools, OAuth, base URLs.
- They can point at **external URLs** you do not control.
- Bad or malicious JSON can break auth, leak secrets, or proxy traffic incorrectly.
- **Read the JSON** before importing. Prefer self-hosted repos you trust.
- You are responsible for what you install.

Use at your own risk. Official Aurora components do **not** go through this store.

---

## Rules

1. **No malware / credential theft** — no exfiltration of keys, tokens, or user data.
2. **No remote code** outside what the extension JSON declares (headers/tools/files).
3. **Honest metadata** — real `name`, `tagline`, `author`, `homepage`.
4. **No trademark abuse** — do not impersonate Aurora or third parties.
5. **No spam** — one quality extension beats ten clones.
6. **Breaking change = new file or bump** — keep old JSON importable when possible.
7. **You own your PR** — respond to review comments or the PR goes stale.

Maintainers may reject or remove any extension at any time.

---

## Submit a PR (add an extension)

1. Fork this repository (or open a PR against the community fork).
2. Add one file:

   ```
   extensions/{id}.extension.json
   ```

3. `{id}` must match the `id` field: lowercase, `a-z0-9-`, no spaces.
4. Validate JSON locally:

   ```bash
   python3 -m json.tool extensions/my-ext.extension.json > /dev/null
   ```

5. Open a PR with:
   - What the extension does
   - Base URL / auth notes
   - Why the community needs it

### Minimal example

```json
{
  "schema": 1,
  "id": "my-ext",
  "name": "My Extension",
  "tagline": "Short one-liner",
  "description": "What it changes on the gateway.",
  "author": "you",
  "tags": ["custom"],
  "base_url": "https://api.example.com/v1",
  "headers": [],
  "ui": { "accent": "#cba6f7" }
}
```

---

## Extension JSON (for authors)

Imported by Aurora as **Sidecar → Extensions → Import** or:

```bash
curl -X POST http://gateway:7841/admin/api/v1/sidecar/extensions/import \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://store/extensions/my-ext.extension.json"}'
```

### Top-level fields

| Field | Type | Description |
|-------|------|-------------|
| `schema` | number | Schema version (use `1`) |
| `id` | string | Unique id (`a-z0-9-`) |
| `name` | string | Display name |
| `tagline` | string | Short description |
| `description` | string | Long description |
| `author` | string | Author / team |
| `homepage` | string | Project URL |
| `tags` | string[] | Search tags |
| `type` | string | `sidecar` or `theme` |
| `base_url` | string | Sidecar base URL on apply |
| `user_agent` | string | Optional UA override |
| `default_auth` | string | Default `Authorization` scheme |
| `headers` | object[] | Header rules for Session Hub |
| `tool_schemas` | object[] | Tools to inject upstream |
| `settings` | object | Sidecar knobs (`base_url`, `oauth_server`, …) |
| `oauth` | object | Device-flow OAuth (`server`, `client_id`, `verification_base`) |
| `files` | object | Files materialized on apply (path → content) |
| `provides` | object | `{ provider_types, features }` |
| `ui` | object | Dashboard presentation (see below) |
| `requirements` | string[] | Human-readable install requirements |
| `builtin` | bool | Always `false` in this store |

### Header rule (`headers[]`)

```json
{ "name": "x-session", "mode": "generate", "prefix": "s_", "length": 24, "charset": "hex" }
```

Modes: `generate` | `map_or_generate` | `value` | (gateway-specific).

### UI contributions (`ui`) — full dashboard surface

Applied only after the operator clicks **Apply** on the extension.

| Field | Description |
|-------|-------------|
| `accent` | Hex color for highlights |
| `docs_url` / `help` | Docs link / help text in settings |
| `fields` | Dynamic form fields for sidecar settings |
| `theme` | Restricted CSS vars (`--accent`, `--bg`, `--text`, …) |
| `nav[]` | Sidebar entries: `{ id, label, to, icon, order }` |
| `hide_nav[]` | Hide built-in nav labels/paths |
| `banners[]` | Banners above page content |
| `widgets[]` | Cards on Overview / Settings (`slot`, `kind`, `body`, `stats`, `links`) |
| `pages[]` | Full pages under `/admin/dashboard/ext/{path}` with `blocks[]` |
| `settings_tabs[]` | Extra Settings tabs with `blocks[]` |
| `hide_settings_tabs[]` | Hide built-in settings tab ids |

**Page blocks** (`blocks[]` / `settings_tabs[].blocks`): structured only — no raw HTML/JS.

```json
{ "kind": "heading", "text": "Getting started" }
{ "kind": "text", "text": "Plain paragraph" }
{ "kind": "code", "language": "bash", "text": "curl …" }
{ "kind": "list", "items": ["step one", "step two"] }
{ "kind": "links", "links": [{ "label": "Docs", "href": "https://…" }] }
{ "kind": "kv", "kv": [{ "k": "Region", "v": "eu" }] }
{ "kind": "divider" }
```

Nav `to`: path under `/admin/dashboard` (relative slug becomes `/admin/dashboard/ext/…`), or absolute `https://…`.

Icons: whitelist only (`layout`, `box`, `layers`, `network`, `database`, `terminal`, `settings`, `shield`, `key`, `workflow`, `book`, `puzzle`, `plugin`, `message`, …).

---

## Bundled extensions

### OpenCode — split into 2

| id | role |
|----|------|
| `opencode` | **CLI emulation** — adds the whole `opencode` provider type (`provides.provider_types` + `inject_tool_types`), client headers, tools and files (the CLI profile) |
| `opencode-oauth` | **Device-flow OAuth only** (`provides.features: ["oauth"]`, no provider type, no tools) |

Install `opencode` for the provider type and client signature; add `opencode-oauth` to wire device-flow auth.

### Themes

Pure-UI extensions (`type: "theme"`, tagged `theme`) — no `base_url`, headers or tools.
Apply the extension in the dashboard to switch the theme; disable it to revert.

| id | description |
|----|-------------|
| `theme-minimal` | Flat zero-radius minimal theme, warm sand accent |
| `theme-catppuccin-mocha` | Catppuccin Mocha (dark) |
| `theme-catppuccin-latte` | Catppuccin Latte (light) |
| `theme-catppuccin-frappe` | Catppuccin Frappé |
| `theme-catppuccin-macchiato` | Catppuccin Macchiato |

Theme extensions expose editable color fields (accent, background, surface, text,
border, radius) under `ui.fields`.

---

## Hosting

Plain static files served by **GitHub Pages** from this repository root.
No server config needed. Add the store base URL in Aurora under
**Settings → Extensions** (the gateway fetches `{base}/api/v1/extensions.json`).

---

## Layout

```
index.html          # human catalog (aggregates every repo below)
style.css
script.js
README.md
repos.json            # curated community repos (PR to add yours)
api/v1/extensions.json   # served as GET /api/v1/extensions.json
extensions/
  {id}.extension.json      # sidecar extensions (opencode, opencode-oauth, …)
  theme-*.extension.json   # theme extensions (pure UI)
  …
```

## Repos

The catalog page is **multi-repo**: it merges extensions from

1. **this store** (always first),
2. **curated repos** listed in `repos.json`,
3. **repos you add** in the page (kept in the browser's `localStorage`).

Each card is labelled with the repo it came from, and the **Repos** panel lists
every source with its extension count (a failing repo is reported inline instead
of breaking the page).

### Adding a repo

**From the page** — paste a store URL (must be `http(s)://…`) into the Repos
panel; it is remembered in this browser and you can remove it again.

**For everyone** — add an entry to `repos.json` and open a PR:

```json
{
  "repos": [
    { "name": "My Store", "url": "https://example.github.io/my-store" }
  ]
}
```

A repo must expose the same two static paths as this store
(`/api/v1/extensions.json` and `/extensions/{id}.extension.json`).

### In Aurora

Add each store base URL under **Settings → Extensions** — Aurora browses one
store at a time, the aggregation on this page is only for humans.

## API (what Aurora parses)

| Path | Response |
|------|----------|
| `GET /api/v1/extensions.json` | `{ "extensions": [ { id, name, tagline, type, version, author, tags } ] }` |
| `GET /extensions/{id}.extension.json` | full extension JSON |

Static hosts serve only these real file paths, which is why both this page and
Aurora fetch them directly. Aurora additionally fills in a `raw_url` per entry
when browsing a store.

No other endpoints.
