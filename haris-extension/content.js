/* حارس — content script: analyses the page and warns the user before a risky step. */
(function () {
  "use strict";
  if (window.top !== window || window.__harisLoaded) return;
  window.__harisLoaded = true;

  let ctx = null, result = null, acked = false, overlayHost = null, pillHost = null, lastFieldCount = -1;

  const send = (msg) => new Promise((resolve) => {
    try { chrome.runtime.sendMessage(msg, (r) => resolve(chrome.runtime.lastError ? null : r)); }
    catch { resolve(null); }
  });

  // ------------------------------------------------------------------ UI
  const SHIELD = '<svg viewBox="0 0 512 512" width="26" height="26" fill="#fff" aria-hidden="true"><path d="M466.5 83.7l-192-80a48.15 48.15 0 0 0-36.9 0l-192 80C27.7 91.1 16 108.6 16 128c0 198.5 114.5 335.7 221.5 380.3 11.8 4.9 25.1 4.9 36.9 0C360.1 472.6 496 349.3 496 128c0-19.4-11.7-36.9-29.5-44.3zM256.1 446.3l-.1-381 175.9 73.3c-3.3 151.4-82.1 261.1-175.8 307.7z"/></svg>';

  const CSS = `
    :host{all:initial}
    .back{position:fixed;inset:0;background:rgba(15,27,51,.62);display:flex;align-items:center;justify-content:center;
      z-index:2147483647;font-family:Tahoma,Arial,sans-serif;direction:rtl;animation:fade .18s ease-out}
    @keyframes fade{from{opacity:0}}
    .card{width:min(540px,92vw);background:#fff;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.35);overflow:hidden;color:#1B2740}
    .hd{display:flex;align-items:center;gap:12px;padding:16px 20px;color:#fff}
    .hd.high{background:#B4232A} .hd.medium{background:#B7791F} .hd.ok{background:#1F7A6F}
    .hd h2{margin:0;font-size:20px;font-weight:bold}
    .hd small{display:block;opacity:.9;font-size:12px;margin-top:2px}
    .bd{padding:16px 22px 6px}
    .lead{margin:0 0 10px;font-size:15px;font-weight:bold}
    ul{margin:0;padding:0;list-style:none}
    li{position:relative;padding:7px 18px 7px 0;font-size:15px;line-height:1.6}
    li:before{content:"";position:absolute;right:0;top:16px;width:8px;height:8px;border-radius:50%;background:#1F7A6F}
    li.known:before{background:#B4232A} li.known{font-weight:bold;color:#8A1C22}
    details{margin:10px 0 4px;font-size:13px;color:#5A6478}
    details summary{cursor:pointer}
    details p{direction:ltr;text-align:left;margin:6px 0;line-height:1.5}
    .priv{font-size:12px;color:#6B7689;margin:10px 0 0}
    .ft{display:flex;gap:10px;padding:14px 22px 20px}
    button{flex:1;padding:12px;border-radius:10px;font-size:15px;font-family:inherit;cursor:pointer;border:1px solid #DCE2EC;background:#fff;color:#5A6478}
    button.safe{background:#1F7A6F;color:#fff;border-color:#1F7A6F;font-weight:bold}
    .pill{position:fixed;bottom:18px;left:18px;z-index:2147483646;background:#B4232A;color:#fff;font-family:Tahoma,Arial,sans-serif;
      direction:rtl;font-size:13px;padding:9px 14px;border-radius:99px;box-shadow:0 6px 20px rgba(0,0,0,.25);cursor:pointer;display:flex;gap:8px;align-items:center}
    .pill.medium{background:#B7791F}`;

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function showOverlay(trigger) {
    if (!result || overlayHost) return;
    removePill();
    overlayHost = document.createElement("haris-alert");
    const sh = overlayHost.attachShadow({ mode: "closed" });
    const lead = trigger === "field"
      ? "قبل أن تكتب بياناتك هنا، انتبه:"
      : trigger === "submit" ? "قبل أن ترسل بياناتك، انتبه:" : "رصد حارس مؤشرات احتيال في هذه الصفحة:";
    const items = result.signals.map((s) => `<li class="${s.code === "known_threat" ? "known" : ""}">${esc(s.ar)}</li>`).join("");
    const en = result.signals.map((s) => `<p>• ${esc(s.en)}</p>`).join("");
    const title = result.level === "high" ? "حارس: توقّف قبل المتابعة" : "حارس: تحقّق قبل المتابعة";
    sh.innerHTML = `<style>${CSS}</style>
      <div class="back" role="alertdialog" aria-modal="true" aria-labelledby="t">
        <div class="card">
          <div class="hd ${result.level}">${SHIELD}<div><h2 id="t">${title}</h2><small>Haris · ${esc(result.host)}</small></div></div>
          <div class="bd">
            <p class="lead">${lead}</p>
            <ul>${items}</ul>
            <details><summary>English</summary>${en}</details>
            <p class="priv">حارس لا يقرأ ولا يرسل ما تكتبه. القرار لك.</p>
          </div>
          <div class="ft">
            <button class="safe" id="b">العودة بأمان</button>
            <button id="c">أفهم المخاطرة، متابعة</button>
          </div>
        </div>
      </div>`;
    document.documentElement.appendChild(overlayHost);
    sh.getElementById("b").addEventListener("click", () => send({ type: "goBack" }));
    sh.getElementById("c").addEventListener("click", () => {
      acked = true;
      send({ type: "ack", host: location.host });
      overlayHost.remove();
      overlayHost = null;
      showPill();
    });
    sh.getElementById("b").focus();
  }

  function showPill() {
    if (pillHost || !result || result.level === "none") return;
    pillHost = document.createElement("haris-pill");
    const sh = pillHost.attachShadow({ mode: "closed" });
    sh.innerHTML = `<style>${CSS}</style><div class="pill ${result.level}" title="حارس">⚠ حارس: صفحة مشبوهة، اضغط للتفاصيل</div>`;
    sh.querySelector(".pill").addEventListener("click", () => { acked = false; showOverlay("pill"); });
    document.documentElement.appendChild(pillHost);
  }
  function removePill() { if (pillHost) { pillHost.remove(); pillHost = null; } }

  // ------------------------------------------- stop the risky step itself
  function isSensitiveField(el) {
    return result && result._sensitiveEls && result._sensitiveEls.includes(el);
  }
  document.addEventListener("focusin", (e) => {
    if (!result || acked || result.level === "none") return;
    if (isSensitiveField(e.target)) { e.target.blur(); showOverlay("field"); }
  }, true);
  document.addEventListener("submit", (e) => {
    if (!result || acked || result.level === "none") return;
    const form = e.target;
    if (result._sensitiveEls.some((el) => form.contains(el))) { e.preventDefault(); e.stopPropagation(); showOverlay("submit"); }
  }, true);

  // --------------------------------------------------------------- run
  async function run() {
    if (!ctx) ctx = await send({ type: "context", url: location.href });
    if (!ctx) return;
    acked = acked || ctx.ack;
    result = HarisAnalyzer.analyze(document, location, ctx);
    const { _sensitiveEls, ...shareable } = result;
    await send({ type: "result", result: shareable });
    if (result.level === "high" && !acked) showOverlay("load");
    else if (result.level !== "none") showPill();
  }

  // Phishing kits often draw the form after the page loads: look again when fields appear.
  let timer = null;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const n = document.querySelectorAll("input, textarea, select").length;
      if (n !== lastFieldCount) { lastFieldCount = n; if (!overlayHost) run(); }
    }, 700);
  }).observe(document.documentElement, { childList: true, subtree: true });

  lastFieldCount = document.querySelectorAll("input, textarea, select").length;
  run();
})();
