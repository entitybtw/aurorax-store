const $ = (s) => document.querySelector(s);

/**
 * Static extension repo API (works on plain static hosts, e.g. GitHub Pages):
 *   GET ./api/v1/extensions.json              → { extensions: [info…] }
 *   GET ./extensions/{id}.extension.json      → raw extension JSON
 *
 * The page always fetches the real files, so it works on any static host.
 */
const API_LIST = "./api/v1/extensions.json";

function apiRaw(id) {
  return `./extensions/${encodeURIComponent(id)}.extension.json`;
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

let listCache = [];
let debounceTimer;
let loadSeq = 0;

function matches(e, q, tag) {
  if (tag && !(e.tags || []).some((t) => String(t).toLowerCase() === tag)) return false;
  if (!q) return true;
  const hay = [e.id, e.name, e.tagline, e.author, ...(e.tags || [])]
    .join(" ")
    .toLowerCase();
  return q.split(/\s+/).every((part) => hay.includes(part));
}

function loadMeta() {
  $("#stats").innerHTML = `<span><b>${listCache.length}</b> extensions</span>`;
  const tags = new Set();
  for (const e of listCache) for (const t of e.tags || []) tags.add(t);
  const tagSel = $("#tag");
  const current = tagSel.value;
  tagSel.innerHTML =
    `<option value="">All tags</option>` +
    [...tags].sort().map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
  tagSel.value = current;
}

async function loadList() {
  const el = $("#catalog");
  el.hidden = false;
  $("#detail").hidden = true;
  const seq = ++loadSeq;
  el.innerHTML = `<div class="empty">Loading…</div>`;
  try {
    if (!listCache.length) {
      const data = await fetchJSON(API_LIST);
      listCache = Array.isArray(data?.extensions) ? data.extensions : [];
    }
    if (seq !== loadSeq) return;
    loadMeta();
    if (seq !== loadSeq) return;
    const q = $("#q").value.trim().toLowerCase();
    const tag = $("#tag").value;
    const list = listCache.filter((e) => matches(e, q, tag));
    if (!list.length) {
      el.innerHTML = `<div class="empty">No extensions match.</div>`;
      return;
    }
    el.innerHTML =
      `<div class="grid">` +
      list.map((e) => `
        <article class="card" data-id="${escapeHtml(e.id)}" tabindex="0">
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
            ${e.author ? `<span>${escapeHtml(e.author)}</span>` : ""}
            <span>${escapeHtml(e.type || "sidecar")}</span>
          </div>
        </article>
      `).join("") +
      `</div>`;

    el.querySelectorAll(".card").forEach((card) => {
      const open = () => openDetail(card.dataset.id);
      card.addEventListener("click", open);
      card.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") open();
      });
    });
  } catch (e) {
    if (seq !== loadSeq) return;
    el.innerHTML = `<div class="error">${escapeHtml(e.message)}</div>
      <p class="empty" style="margin-top:12px">
        Expected <code class="mono">GET ./api/v1/extensions.json</code> →
        <code class="mono">{ extensions: [...] }</code>.
      </p>`;
  }
}

async function openDetail(id) {
  $("#catalog").hidden = true;
  const d = $("#detail");
  d.hidden = false;
  d.innerHTML = `<div class="empty">Loading…</div>`;
  try {
    const meta = listCache.find((x) => x.id === id);
    if (!meta) throw new Error("extension not found");
    const rawUrl = apiRaw(id);
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
          <dt>Homepage</dt><dd>${full.homepage ? `<a href="${escapeHtml(full.homepage)}" target="_blank" rel="noreferrer">${escapeHtml(full.homepage)}</a>` : "—"}</dd>
          <dt>Base URL</dt><dd>${escapeHtml(full.base_url || "—")}</dd>
          <dt>Raw</dt><dd><a href="${escapeHtml(rawUrl)}">${escapeHtml(rawUrl)}</a></dd>
        </dl>
        ${(full.requirements || []).length ? `
          <div class="panel" style="margin-top:14px;border-color:rgba(229,200,144,.4)">
            <strong>Requirements</strong>
            <ul style="margin:6px 0 0 18px;padding:0">${full.requirements.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
          </div>` : ""}
        ${headers ? `<div class="headers">${headers}</div>` : ""}
        <div class="actions">
          <a class="primary" style="display:inline-block;text-decoration:none;padding:10px 14px;border-radius:var(--radius)"
             href="${escapeHtml(rawUrl)}" download>Download JSON</a>
          <button id="copy-url" type="button">Copy raw URL</button>
        </div>
        <pre class="json" id="raw-json"></pre>
      </div>`;
    $("#back").addEventListener("click", loadList);
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
    $("#back").addEventListener("click", loadList);
  }
}

$("#q").addEventListener("input", () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(loadList, 200);
});
$("#tag").addEventListener("change", loadList);
$("#refresh").addEventListener("click", () => {
  listCache = [];
  loadList();
});

loadList();
