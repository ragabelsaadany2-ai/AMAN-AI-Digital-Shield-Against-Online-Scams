/* حارس — background service worker.
 * - Remembers the last search in each tab (the "journey"), kept only in this browser session.
 * - Asks the Al-Tu'm server whether a page's link is already known.
 * - Reports suspicious pages to the shared store (address without query string, signals only).
 */
importScripts("analyzer.js");

const DEFAULTS = { server: "http://127.0.0.1:8080", share: true };
const JOURNEY_TTL = 30 * 60 * 1000;
let brandsCache = null;

async function settings() {
  const s = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...s };
}

async function brands() {
  if (!brandsCache) {
    const r = await fetch(chrome.runtime.getURL("brands.json"));
    brandsCache = (await r.json()).brands;
  }
  return brandsCache;
}

// ------------------------------------------------------------ journey
function searchQuery(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { return null; }
  const h = u.hostname, p = u.pathname;
  if (/(^|\.)google\.[a-z.]+$/.test(h) && p.startsWith("/search")) return u.searchParams.get("q");
  if (/(^|\.)bing\.com$/.test(h) && p.startsWith("/search")) return u.searchParams.get("q");
  if (/(^|\.)duckduckgo\.com$/.test(h)) return u.searchParams.get("q");
  if (/(^|\.)search\.yahoo\.com$/.test(h)) return u.searchParams.get("p");
  if (p === "/demo/search") return u.searchParams.get("q");   // the offline demo search page
  return null;
}

chrome.tabs.onUpdated.addListener(async (tabId, info) => {
  if (!info.url) return;
  const q = searchQuery(info.url);
  if (q && q.trim()) {
    const category = HarisAnalyzer.categoryOfText(q);
    await chrome.storage.session.set({ ["j:" + tabId]: { query: q.trim().slice(0, 80), category, ts: Date.now() } });
  }
});

chrome.tabs.onCreated.addListener(async (tab) => {
  if (!tab.openerTabId) return;   // a result opened in a new tab keeps the search that led to it
  const key = "j:" + tab.openerTabId;
  const got = await chrome.storage.session.get(key);
  if (got[key]) await chrome.storage.session.set({ ["j:" + tab.id]: got[key] });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(["j:" + tabId, "r:" + tabId]);
});

async function journeyFor(tabId) {
  const key = "j:" + tabId;
  const got = await chrome.storage.session.get(key);
  const j = got[key];
  if (!j || Date.now() - j.ts > JOURNEY_TTL || !j.category) return null;
  return j;
}

// ------------------------------------------------------------- server
function pageAddress(urlStr) {
  try { const u = new URL(urlStr); return u.origin + u.pathname; } catch { return ""; }
}

async function fetchJson(url, opts = {}, ms = 2500) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal });
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function checkKnown(urlStr) {
  const { server } = await settings();
  const addr = pageAddress(urlStr);
  if (!addr || addr.startsWith(server + "/api")) return null;
  return fetchJson(`${server}/api/haris/check?url=${encodeURIComponent(addr)}`);
}

const reported = new Set();
async function report(tabUrl, result) {
  const { server, share } = await settings();
  if (!share) return;
  const addr = pageAddress(tabUrl);
  const key = addr + "|" + result.level;
  if (reported.has(key)) return;
  reported.add(key);
  await fetchJson(`${server}/api/haris/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: addr, brand: result.brand, category: result.category, requested: result.requested,
      level: result.level, signals: result.signals.map(s => s.code),
      reasons_ar: result.signals.map(s => s.share),   // no search text, no typed values
    }),
  });
}

// ------------------------------------------------------------ badge
function setBadge(tabId, level) {
  const text = level === "high" ? "!" : level === "medium" ? "?" : "";
  const color = level === "high" ? "#E5484D" : "#E3A008";
  chrome.action.setBadgeText({ tabId, text });
  if (text) chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// ---------------------------------------------------------- messages
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : msg.tabId;
  (async () => {
    if (msg.type === "context") {
      const [b, journey, known] = await Promise.all([brands(), journeyFor(tabId), checkKnown(msg.url)]);
      const host = (() => { try { return new URL(msg.url).host; } catch { return ""; } })();
      const ack = (await chrome.storage.session.get("ack:" + host))["ack:" + host] || false;
      sendResponse({ brands: b, journey, known, ack, serverOnline: known !== null });
    } else if (msg.type === "result") {
      await chrome.storage.session.set({ ["r:" + tabId]: { ...msg.result, url: pageAddress(sender.tab.url), ts: Date.now() } });
      setBadge(tabId, msg.result.level);
      if (msg.result.level === "high" || msg.result.level === "medium") await report(sender.tab.url, msg.result);
      sendResponse({ ok: true });
    } else if (msg.type === "ack") {
      await chrome.storage.session.set({ ["ack:" + msg.host]: true });
      sendResponse({ ok: true });
    } else if (msg.type === "goBack") {
      try { await chrome.tabs.goBack(tabId); }
      catch { await chrome.tabs.update(tabId, { url: "about:blank" }); }
      sendResponse({ ok: true });
    } else if (msg.type === "ping") {
      const { server } = await settings();
      sendResponse({ online: !!(await fetchJson(`${server}/api/haris/ping`)), server });
    } else {
      sendResponse(null);
    }
  })();
  return true;   // keep the channel open for the async reply
});
