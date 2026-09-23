const $ = (s) => document.querySelector(s);

/**
 * Static extension repo API (works on plain static hosts, e.g. GitHub Pages):
 *   GET {base}/api/v1/extensions.json          → { extensions: [info…] }
 *   GET {base}/extensions/{id}.extension.json  → raw extension JSON
 *
 * The page aggregates every repo below: this store itself, curated repos from
 * ./repos.json, and repos the visitor added (kept in this browser).
 */
const REPOS_FILE = "./repos.json";
const LS_KEY = "aurorax-store:repos";
const ORIGIN_REPO = { name: "AuroraX Store", base: ".", source: "origin" };

const state = { repos: [], extensions: [], errors: [] };

function repoCatalogURL(base) {
  return String(base).replace(/\/$/, "") + "/api/v1/extensions.json";
}

function repoRawURL(base, id) {
  return String(base).replace(/\/$/, "") + "/extensions/" + encodeURIComponent(id) + ".extension.json";
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function pill(text, cls = "pill") {
  return `<span class="${cls}">${escapeHtml(text)}</span>`;
}

async function fetchJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

async function fetchText(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

function readLocalRepos() {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((r) => r && typeof r.base === "string" && r.base);
  } catch {
    return [];
  }
}

function writeLocalRepos(list) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(list));
  } catch {
    /* storage unavailable */
  }
}

async function loadRepos() {
  const repos = [ORIGIN_REPO];
  try {
    const data = await fetchJSON(REPOS_FILE);
    const curated = Array.isArray(data?.repos) ? data.repos : [];
    for (const r of curated) {
      if (r && typeof r.url === "string" && r.url) {
        repos.push({ name: r.name || r.url, base: r.url, source: "curated" });
      }
    }
  } catch {
    /* no curated repo list — fine */
  }
  for (const r of readLocalRepos()) {
    repos.push({ name: r.name || r.base, base: r.base, source: "local" });
  }
  return repos;
}

async function loadExtensions() {
  state.repos = await loadRepos();
  const results = await Promise.all(
    state.repos.map(async (repo) => {
      try {
        const data = await fetchJSON(repoCatalogURL(repo.base));
        return { repo, list: Array.isArray(data?.extensions) ? data.extensions : [] };
      } catch (e) {
        return { repo, error: e.message };
      }
    }),
  );

  const merged = [];
  const errors = [];
  results.forEach((entry, repoIndex) => {
    if (entry.error) {
      errors.push(entry);
      return;
    }
    entry.list.forEach((ext, extIndex) => {
      merged.push({ ...ext, _repo: entry.repo, _key: `${repoIndex}:${extIndex}` });
    });
  });
  state.extensions = merged;
  state.errors = errors;
}

function matches(e, q, tag) {
  if (tag && !(e.tags || []).some((t) => String(t).toLowerCase() === tag)) return false;
  if (!q) return true;
  const hay = [e.id, e.name, e.tagline, e.author, e._repo?.name, ...(e.tags || [])]
    .join(" ")
    .toLowerCase();
  return q.split(/\s+/).every((part) => hay.includes(part));
}

function renderMeta() {
  $("#stats").innerHTML =
    `<span><b>${state.extensions.length}</b> extensions</span>` +
    `<span><b>${state.repos.length}</b> repos</span>`;
  const tags = new Set();
  for (const e of state.extensions) for (const t of e.tags || []) tags.add(t);
  const tagSel = $("#tag");
  const current = tagSel.value;
  tagSel.innerHTML =
    `<option value="">All tags</option>` +
    [...tags].sort().map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
  tagSel.value = current;
}

function renderRepos() {
  const ul = $("#repo-list");
  if (!ul) return;
  ul.innerHTML = state.repos
    .map((r, i) => {
      const count = state.extensions.filter((e) => e._repo === r).length;
      const label = r.base === "." ? "(this store)" : r.base;
      return `
        <li class="repo-row">
          <div class="repo-main">
            <b>${escapeHtml(r.name)}</b>
            <span class="mono repo-url">${escapeHtml(label)}</span>
          </div>
          ${pill(r.source, "pill tag")}
          <span class="repo-count">${count}</span>
          ${r.source === "local" ? `<button class="repo-remove" type="button" data-i="${i}">Remove</button>` : ""}
        </li>`;
    })
    .join("");

  ul.querySelectorAll(".repo-remove").forEach((btn) => {
    btn.addEventListener("click", () => {
      const repo = state.repos[Number(btn.dataset.i)];
      writeLocalRepos(readLocalRepos().filter((r) => r.base !== repo.base));
      refresh();
    });
  });

  const errBox = $("#repo-errors");
  if (errBox) {
    errBox.innerHTML = state.errors.length
      ? state.errors
          .map((e) => `<div class="repo-error">${escapeHtml(e.repo.name)}: ${escapeHtml(e.error)}</div>`)
          .join("")
      : "";
  }
}

function renderList() {
  const el = $("#catalog");
  el.hidden = false;
  $("#detail").hidden = true;
  renderMeta();
  const q = $("#q").value.trim().toLowerCase();
  const tag = $("#tag").value;
  const list = state.extensions.filter((e) => matches(e, q, tag));
  if (!list.length) {
    el.innerHTML = `<div class="empty">No extensions match.</div>`;
    return;
  }
  el.innerHTML =
    `<div class="grid">` +
    list
      .map((e) => `
        <article class="card" data-key="${escapeHtml(e._key)}" tabindex="0">
          <div class="row">
            <span class="dot"></span>
            <h3>${escapeHtml(e.name)}</h3>
            ${e.version ? pill("v" + e.version) : ""}
          </div>
          <div class="tagline">${escapeHtml(e.tagline || "")}</div>
          <div class="meta">
            ${pill(e.id)}
            ${(e.tags || []).slice(0, 4).map((t) => pill(t, "pill tag")).join("")}
          </div>
          <div class="meta">
            ${e._repo ? pill(e._repo.name, "pill repo") : ""}
            <span>${escapeHtml(e.type || "sidecar")}</span>
          </div>
        </article>
      `)
      .join("") +
    `</div>`;

  el.querySelectorAll(".card").forEach((card) => {
    const open = () => openDetail(card.dataset.key);
    card.addEventListener("click", open);
    card.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") open();
    });
  });
}

async function openDetail(key) {
  $("#catalog").hidden = true;
  const d = $("#detail");
  d.hidden = false;
  d.innerHTML = `<div class="empty">Loading…</div>`;
  try {
    const meta = state.extensions.find((x) => x._key === key);
    if (!meta) throw new Error("extension not found");
    const rawUrl = repoRawURL(meta._repo.base, meta.id);
    const full = await fetchJSON(rawUrl).catch(() => meta);
    const tags = (full.tags || meta.tags || []).map((t) => pill(t, "pill tag")).join(" ");
    const headers = (full.headers || [])
      .map((h) => {
        const detail = [h.mode, h.prefix, h.length ? `+${h.length}` : null, h.charset, h.value]
          .filter(Boolean)
          .join(" · ");
        return `<div class="header-row"><code>${escapeHtml(h.name)}</code><span>${escapeHtml(detail)}</span></div>`;
      })
      .join("");
    d.innerHTML = `
      <button class="ghost back" id="back" type="button">← Catalog</button>
      <div class="detail">
        <header>
          <div>
            <h2><span class="dot"></span>${escapeHtml(full.name || meta.name)}</h2>
            <div style="color:var(--muted)">${escapeHtml(full.tagline || meta.tagline || "")}</div>
          </div>
          <div class="meta">${pill(full.id || meta.id)} ${full.version ? pill("v" + full.version) : ""} ${tags}</div>
        </header>
        <div class="desc">${escapeHtml(full.description || "")}</div>
        <dl class="kv">
          <dt>Type</dt><dd>${escapeHtml(full.type || "sidecar")}</dd>
          <dt>Author</dt><dd>${escapeHtml(full.author || "—")}</dd>
          <dt>Repo</dt><dd>${escapeHtml(meta._repo?.name || "—")}</dd>
          <dt>Homepage</dt><dd>${full.homepage ? `<a href="${escapeHtml(full.homepage)}" target="_blank" rel="noreferrer">${escapeHtml(full.homepage)}</a>` : "—"}</dd>
          <dt>Base URL</dt><dd>${escapeHtml(full.base_url || "—")}</dd>
          <dt>Raw</dt><dd><a href="${escapeHtml(rawUrl)}">${escapeHtml(rawUrl)}</a></dd>
        </dl>
        ${(full.requirements || []).length ? `
          <div class="panel" style="margin-top:14px;border-color:rgba(229,200,144,.4)">
            <strong>Requirements</strong>
            <ul style="margin:6px 0 0 18px;padding:0">${full.requirements.map((r) => `<li>${escapeHtml(r)}</li>`)}</ul>
          </div>` : ""}
        ${headers ? `<div class="headers">${headers}</div>` : ""}
        <div class="actions">
          <a class="primary" style="display:inline-block;text-decoration:none;padding:10px 14px;border-radius:var(--radius)"
             href="${escapeHtml(rawUrl)}" download>Download JSON</a>
          <button id="copy-url" type="button">Copy raw URL</button>
        </div>
        <pre class="json" id="raw-json"></pre>
      </div>`;
    $("#back").addEventListener("click", renderList);
    $("#copy-url").addEventListener("click", async () => {
      const url = new URL(rawUrl, location.href).href;
      try {
        await navigator.clipboard.writeText(url);
        $("#copy-url").textContent = "Copied";
      } catch {
        prompt("Raw URL:", url);
      }
    });
    try {
      $("#raw-json").textContent = await fetchText(rawUrl);
    } catch {
      /* preview optional */
    }
  } catch (e) {
    d.innerHTML = `<div class="error">${escapeHtml(e.message)}</div>
      <div style="margin-top:12px"><button id="back" type="button">← Catalog</button></div>`;
    $("#back").addEventListener("click", renderList);
  }
}

async function refresh() {
  const el = $("#catalog");
  el.hidden = false;
  $("#detail").hidden = true;
  el.innerHTML = `<div class="empty">Loading…</div>`;
  try {
    await loadExtensions();
    renderRepos();
    renderList();
  } catch (e) {
    el.innerHTML = `<div class="error">${escapeHtml(e.message)}</div>
      <p class="empty" style="margin-top:12px">
        Expected <code class="mono">GET ./api/v1/extensions.json</code> →
        <code class="mono">{ extensions: [...] }</code>.
      </p>`;
  }
}

$("#q").addEventListener("input", () => renderList());
$("#tag").addEventListener("change", renderList);
$("#refresh").addEventListener("click", refresh);

$("#repo-add")?.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const url = $("#repo-url").value.trim().replace(/\/$/, "");
  const name = $("#repo-name").value.trim();
  if (!/^https?:\/\//i.test(url)) {
    alert("Repo URL must start with http:// or https://");
    return;
  }
  const local = readLocalRepos();
  if (!local.some((r) => r.base === url)) {
    local.push({ name: name || url, base: url });
    writeLocalRepos(local);
  }
  $("#repo-url").value = "";
  $("#repo-name").value = "";
  await refresh();
});

refresh();
