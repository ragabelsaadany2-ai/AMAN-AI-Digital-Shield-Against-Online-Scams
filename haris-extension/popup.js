const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const key = "r:" + (tab && tab.id);
  const r = (await chrome.storage.session.get(key))[key];
  const page = $("page");
  if (!r || (tab && r.url && !tab.url.startsWith(r.url))) {
    page.innerHTML = '<div class="muted">لا يفحص حارس هذه الصفحة (صفحات المتصفح الداخلية) أو لم يكتمل الفحص بعد.</div>';
  } else if (r.level === "none") {
    const note = r.official ? `الصفحة على نطاق معتمد لـ«${esc(r.official)}».` : "لم تُرصد مؤشرات احتيال.";
    page.innerHTML = `<div class="st none">✓ لا تنبيهات</div><div class="muted">${note}</div>`;
  } else {
    const t = r.level === "high" ? "⚠ صفحة مشبوهة جداً" : "⚠ تحقّق قبل المتابعة";
    page.innerHTML = `<div class="st ${r.level}">${t}</div><ul>${r.signals.map((s) => `<li>${esc(s.ar)}</li>`).join("")}</ul>`;
  }

  const s = await chrome.storage.local.get({ server: "http://127.0.0.1:8080", share: true });
  $("server").value = s.server;
  $("share").checked = s.share;
  $("server").addEventListener("change", async () => {
    await chrome.storage.local.set({ server: $("server").value.trim().replace(/\/+$/, "") });
    ping();
  });
  $("share").addEventListener("change", () => chrome.storage.local.set({ share: $("share").checked }));

  async function ping() {
    const res = await chrome.runtime.sendMessage({ type: "ping" });
    $("srvdot").className = "dot " + (res && res.online ? "on" : "off");
    $("srv").textContent = res && res.online ? "متصل بالمخزن المشترك" : "غير متصل: يعمل حارس محلياً فقط";
  }
  ping();
})();
