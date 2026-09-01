"use strict";

const state = { data: null, kind: "urls", query: "" };
const labels = Object.freeze({ urls: "URLs", ips: "IP addresses", hashes: "SHA-256 hashes" });
const rows = document.querySelector("#indicator-rows");
const empty = document.querySelector("#empty");
const refreshButton = document.querySelector("#refresh");
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";

function make(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 1800);
}

function safeScore(value) {
  const score = Number(value);
  return Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : 0;
}

function safeHomepage(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.href : "";
  } catch (_error) {
    return "";
  }
}

function renderRows() {
  rows.replaceChildren();
  if (!state.data) return;
  const query = state.query.toLocaleLowerCase();
  const collection = state.data.indicators?.[state.kind];
  const items = Array.isArray(collection) ? collection.filter((item) => {
    const sources = Array.isArray(item.sources) ? item.sources.join(" ") : "";
    return !query || `${item.value || ""} ${sources} ${item.threat || ""}`.toLocaleLowerCase().includes(query);
  }) : [];
  empty.hidden = items.length !== 0;

  for (const item of items) {
    const tr = document.createElement("tr");
    tr.append(make("td", "mt100-rank", String(item.rank || 0).padStart(2, "0")));

    const indicatorCell = make("td", "mt100-indicator", String(item.value || ""));
    indicatorCell.append(make("small", "", String(item.threat || "public threat feed listing")));
    tr.append(indicatorCell);

    const score = safeScore(item.score);
    const scoreCell = make("td", "mt100-score");
    const scoreLine = make("div", "mt100-score-line");
    scoreLine.append(make("strong", "", String(score)));
    const meter = document.createElement("progress");
    meter.max = 100;
    meter.value = score;
    meter.setAttribute("aria-label", `Signal score ${score} out of 100`);
    scoreLine.append(meter);
    scoreCell.append(scoreLine);
    tr.append(scoreCell);

    const sources = Array.isArray(item.sources) ? item.sources.join(" · ") : "";
    tr.append(make("td", "mt100-source-cell", sources));
    const actionCell = document.createElement("td");
    const copy = make("button", "mt100-copy", "Copy");
    copy.type = "button";
    copy.setAttribute("aria-label", `Copy ${String(item.value || "indicator")}`);
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(String(item.value || ""));
        showToast("Indicator copied");
      } catch (_error) {
        showToast("Clipboard access unavailable");
      }
    });
    actionCell.append(copy);
    tr.append(actionCell);
    rows.append(tr);
  }
}

function render() {
  const data = state.data;
  if (!data) return;
  for (const kind of Object.keys(labels)) {
    document.querySelector(`#count-${kind}`).textContent = String(data.counts?.[kind] ?? 0);
  }
  document.querySelector("#updated").textContent = data.generated_at
    ? `Snapshot ${new Date(data.generated_at).toLocaleString()}`
    : "No local snapshot yet";
  const sources = Array.isArray(data.sources) ? data.sources : [];
  document.querySelector("#methodology").textContent = String(data.methodology || "No methodology available.");
  document.querySelector("#list-kicker").textContent = `TOP 100 · ${labels[state.kind].toUpperCase()}`;

  const sourceList = document.querySelector("#source-list");
  sourceList.replaceChildren();
  for (const source of sources) {
    const card = make("article", "mt100-source-card");
    const copy = document.createElement("div");
    const homepage = safeHomepage(source.homepage);
    const name = homepage ? make("a", "", String(source.name || "Unknown source")) : make("strong", "", String(source.name || "Unknown source"));
    if (homepage) {
      name.href = homepage;
      name.target = "_blank";
      name.rel = "noopener noreferrer";
    }
    copy.append(name, make("small", "", `${Number(source.items) || 0} accepted indicators`));
    const status = source.status === "ok" ? "ok" : "error";
    card.append(copy, make("span", `mt100-badge ${status}`, status));
    sourceList.append(card);
  }
  renderRows();
}

async function fetchData(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) {
    throw new Error(response.status === 401 ? "Your session has expired" : "Unable to load threat intelligence");
  }
  return response.json();
}

async function load() {
  state.data = await fetchData("/api/malicious-top100/data", { headers: { Accept: "application/json" } });
  render();
}

async function refresh() {
  refreshButton.disabled = true;
  refreshButton.textContent = "Refreshing…";
  try {
    state.data = await fetchData("/api/malicious-top100/refresh", {
      method: "POST",
      headers: { Accept: "application/json", "X-CSRF-Token": csrfToken },
    });
    render();
    showToast("Threat feeds refreshed");
  } catch (error) {
    showToast(error.message);
  } finally {
    refreshButton.disabled = false;
    refreshButton.textContent = "Refresh intelligence ↻";
  }
}

for (const tab of document.querySelectorAll(".mt100-tab")) {
  tab.addEventListener("click", () => {
    const requestedKind = tab.dataset.kind;
    if (!Object.hasOwn(labels, requestedKind)) return;
    state.kind = requestedKind;
    for (const peer of document.querySelectorAll(".mt100-tab")) {
      const active = peer === tab;
      peer.classList.toggle("active", active);
      peer.setAttribute("aria-selected", String(active));
    }
    renderRows();
  });
}

document.querySelector("#search").addEventListener("input", (event) => {
  state.query = String(event.target.value || "").slice(0, 2048);
  renderRows();
});
refreshButton.addEventListener("click", refresh);
document.querySelector("#export-csv").addEventListener("click", () => {
  window.location.assign(`/api/malicious-top100/export?type=${encodeURIComponent(state.kind)}&format=csv`);
});
document.querySelector("#export-json").addEventListener("click", () => {
  window.location.assign(`/api/malicious-top100/export?type=${encodeURIComponent(state.kind)}&format=json`);
});

load().catch((error) => showToast(error.message));
