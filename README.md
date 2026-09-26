# AuroraX Store

Static extension catalog for the [AuroraX gateway](https://github.com/entitybtw/aurora).
Drop extension JSON files into `extensions/` — the page and API expose **info +
raw content** only. Gateway-side repo URLs are managed in
**Settings → Extensions**.

| What | Where |
|------|-------|
| Gateway source code | [github.com/entitybtw/aurora](https://github.com/entitybtw/aurora) |
| Store (live catalog) | [entitybtw.github.io/aurorax-store](https://entitybtw.github.io/aurorax-store) |
| Store source code | [github.com/entitybtw/aurorax-store](https://github.com/entitybtw/aurorax-store) |
| Docker image | [hub.docker.com/r/entbtw/aurora](https://hub.docker.com/r/entbtw/aurora) |

---

## Install an extension

1. In the gateway open **Settings → Extensions → Browse store** (this repo's
   URL is added as a store base, or import one extension by URL):

   ```bash
   curl -X POST http://gateway:7841/admin/api/v1/sidecar/extensions/import \
     -H 'Content-Type: application/json' \
     -d '{"url":"https://entitybtw.github.io/aurorax-store/extensions/my-ext.extension.json"}'
   ```

2. Review the imported JSON in the dashboard, then click **Enable** / **Apply**.
3. Settings changes made after install are yours — **Reset to defaults**
   restores the shipped values (only while a sync source is configured).

Extensions update in place: **Update from source** re-fetches the JSON and
keeps your saved settings, applied state and position.

---

## Safety — read before installing

> **Disclaimer:** Everything here is shared for **informational and
> educational purposes**. Extensions can route your traffic to, and interact
> with, **third-party services in ways that may conflict with those services'
> terms of service**. Review the JSON and the target service's rules before
> use; you are responsible for any consequences, including suspensions or
> bans.

Everything in this store is **community-added; there is no review guarantee**.

- Extensions can **change gateway behavior**: headers, tools, auth defaults,
  base URLs, tool injection.
- They can point traffic at **external URLs** you do not control.
- Broken or hostile JSON can leak secrets or proxy traffic incorrectly.
- **Read the JSON before importing.** Prefer repos you host yourself.
- You are responsible for what you install. Official gateway components do
  not come from this store.

## Rules for submissions

1. **No malware / credential theft** — no exfiltration of keys or user data.
2. **No remote code** beyond what the JSON declares (headers / tools / files).
3. **Honest metadata** — real `name`, `tagline`, `author`, `homepage`.
4. **No trademark abuse** — do not impersonate the gateway or third parties.
5. **No spam** — one useful extension beats ten clones.
6. **Breaking change = new file or version bump** — keep old JSON importable.
7. **You own your PR** — answer review comments or it goes stale.

Maintainers may reject or remove any extension at any time.

---

## Add an extension (PR)

1. Fork the repository and add exactly one file:

   ```
   extensions/{id}.extension.json
   ```

2. `{id}` must match the JSON `id` field: lowercase `a-z0-9-`, no spaces.
3. Validate locally:

   ```bash
   python3 -m json.tool extensions/my-ext.extension.json > /dev/null
   ```

4. Open a PR describing: what it does, base URL / auth notes, and why the
   community needs it.

Minimal example:

```json
{
  "schema": 1,
  "id": "my-ext",
  "name": "My Extension",
  "tagline": "Short one-liner",
  "description": "What it changes on the gateway.",
  "author": "you",
  "base_url": "https://api.example.com/v1",
  "headers": [],
  "ui": { "accent": "#cba6f7" }
}
```

---

## Extension JSON reference (for authors)

Imported by the gateway via **Settings → Extensions → Import** (URL above).

### Three layers

An extension may mix all three:

| Layer | Typical `type` | Role |
|-------|----------------|------|
| **Theme** | `theme` | Dashboard palette via `ui.theme` / `ui.theme_light` / `ui.theme_dark` |
| **Preset** | `sidecar` | Sidecar routing, headers, tools, retries, auth endpoints |
| **Addon** | `sidecar` / `addon` | Optional capabilities via `provides` (`provider_types`, `features`) and `files` |

Gateway-side deep dives: `documentation/extensions/{README,THEMES,PRESETS,ADDONS}.md`
in the gateway repo.

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
| `type` | string | `sidecar` or `theme` |
| `base_url` | string | Sidecar base URL on apply |
| `user_agent` | string | Optional UA override |
| `default_auth` | string | Default `Authorization` scheme |
| `headers` | object[] | Header rules for Session Hub |
| `tool_schemas` | object[] | Tools to inject upstream |
| `settings` | object | Sidecar knobs (`base_url`, `forward_headers`, `sidecar_url`, …) |
| `oauth` | object | Auth-flow wiring (`server`, `client_id`, `verification_base`) |
| `files` | object | Files materialized on apply (path → content) |
| `provides` | object | `{ provider_types, features }` |
| `ui` | object | Dashboard presentation (see below) |
| `requirements` | string[] | Human-readable install requirements |
| `builtin` | bool | Always `false` in this store |

### Header rules (`headers[]`)

```json
{ "name": "x-session", "mode": "map_or_generate", "prefix": "ses_", "length": 26, "charset": "hex" }
```

Modes: `map_or_generate` (default), `map`, `generate`, `passthrough`, `static`,
`random_from_list`, `remove`.

### UI contributions (`ui`)

Applied only after the operator clicks **Apply**.

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

**Page blocks** (`blocks[]` / `settings_tabs[].blocks`) are structured only —
no raw HTML/JS:

```json
{ "kind": "heading", "text": "Getting started" }
{ "kind": "text", "text": "Plain paragraph" }
{ "kind": "code", "language": "bash", "text": "curl …" }
{ "kind": "list", "items": ["step one", "step two"] }
{ "kind": "links", "links": [{ "label": "Docs", "href": "https://…" }] }
{ "kind": "kv", "kv": [{ "k": "Region", "v": "eu" }] }
{ "kind": "divider" }
```

Nav `to`: a path under `/admin/dashboard` (a relative slug becomes
`/admin/dashboard/ext/…`) or an absolute `https://…`.
Icons are whitelisted: `layout`, `box`, `layers`, `network`, `database`,
`terminal`, `settings`, `shield`, `key`, `workflow`, `book`, `puzzle`,
`plugin`, `message`, …

---

## Bundled extensions

### Emulation profile — split into 2

| id | role |
|----|------|
| `opencode` | **OpenCode Emulation** — adds the `cli-emulation` provider type, client headers, tools injected for `cli-emulation` and `vllm` providers, `sidecar_url` / `forward_headers` settings and files |
| `opencode-oauth` | **Device-flow auth only** (`provides.features: ["oauth"]`, no provider type, no tools) |

Install `opencode` for the provider type and client signature; add
`opencode-oauth` to wire device-flow auth. Pools whose members report type
`vllm` still receive tool injection and streaming via `inject_tool_types`.

### Authorization-code auth

| id | role |
|----|------|
| `claude-oauth` | **Claude OAuth 2.0** — authorization-code + PKCE wiring (`authorize_url`, `token_url`, `client_id`, `scopes`) with a shipped settings page. Supplies the `oauth` feature only; pair it with a provider-type extension. |

### Themes

Pure-UI extensions (`type: "theme"`) — no `base_url`, headers or tools. The
flat minimal theme is the gateway default; these are optional alternatives.
Apply to switch, disable to revert.

| id | description |
|----|-------------|
| `theme-catppuccin-mocha` | Mocha flavor — dark + light variants |
| `theme-catppuccin-frappe` | Frappé flavor — dark + light variants |
| `theme-catppuccin-macchiato` | Macchiato flavor — dark + light variants |

Every theme ships both `theme_dark` and `theme_light`, so the light/dark
switch picks the matching palette from the same installed theme. Editable color
fields (accent, background, surface, text, border, radius) live under
`ui.fields`.

---

## Hosting & API

Plain static files served by **GitHub Pages** from this repository root — no
server config. Add the store base URL in the gateway under
**Settings → Extensions**.

| Path | Response |
|------|----------|
| `GET /api/v1/extensions.json` | `{ "extensions": [ { id, name, tagline, type, version, author } ] }` |
| `GET /extensions/{id}.extension.json` | full extension JSON |

Both paths are the real files below — the catalog page and the gateway fetch
them directly. The gateway additionally fills a `raw_url` per entry when
browsing. No other endpoints exist.

## Layout

```
index.html                 # human catalog (aggregates every repo below)
style.css
script.js
README.md
api/v1/extensions.json     # GET /api/v1/extensions.json
extensions/
  {id}.extension.json        # emulation / auth extensions
  theme-*.extension.json     # theme extensions (pure UI)
```
