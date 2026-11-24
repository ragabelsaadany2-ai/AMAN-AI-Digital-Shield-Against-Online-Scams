/* حارس — page analyzer.
 * Pure logic over the page's structure. It looks at what KIND of data a form asks for
 * (password, card, code…) and never reads the values a user types.
 */
(function (root) {
  "use strict";

  const ITEM_AR = {
    password: "كلمة المرور", email_password: "كلمة مرور بريدك الإلكتروني", otp: "رمز التحقق",
    card: "بيانات البطاقة", cvv: "رمز الأمان (CVV)", id_number: "رقم الهوية",
  };
  const ITEM_EN = {
    password: "your password", email_password: "your email password", otp: "a verification code",
    card: "your card details", cvv: "your card security code", id_number: "your ID number",
  };
  const PLURAL_AR = { shipping: "شركات الشحن", bank: "البنوك", government: "الجهات الحكومية", telecom: "شركات الاتصالات" };
  const PLURAL_EN = { shipping: "Shipping companies", bank: "Banks", government: "Government services", telecom: "Telecom companies" };
  const SERVICE_AR = { shipping: "خدمة شحن", bank: "خدمة بنكية", government: "خدمة حكومية", telecom: "خدمة اتصالات" };
  const SERVICE_EN = { shipping: "a shipping service", bank: "a banking service", government: "a government service", telecom: "a telecom service" };

  // What each kind of service may legitimately ask for (on its official domain).
  const EXPECTED = {
    shipping: [],
    bank: ["password", "email_password", "otp", "card", "cvv"],
    government: ["password", "email_password", "otp", "card", "cvv", "id_number"],
    telecom: ["password", "email_password", "otp", "card", "cvv"],
  };
  const SENSITIVE = ["email_password", "password", "otp", "card", "cvv", "id_number"];

  const CATEGORY_WORDS = {
    shipping: ["شحن", "شحنة", "شحنتي", "تتبع", "طرد", "توصيل", "track", "tracking", "parcel", "shipment", "delivery", "courier"],
    bank: ["بنك", "مصرف", "حسابي", "بطاقتي", "تحويل", "bank", "banking", "account login"],
    government: ["مخالفة", "مخالفات", "إقامة", "اقامة", "تأشيرة", "الهوية", "شرطة", "fine", "visa", "emirates id", "police", "traffic"],
    telecom: ["فاتورة", "رصيد", "شحن رصيد", "bill", "recharge", "etisalat", "اتصالات"],
  };

  function categoryOfText(text) {
    const t = (text || "").toLowerCase();
    let best = null, hits = 0;
    for (const [cat, words] of Object.entries(CATEGORY_WORDS)) {
      const n = words.filter(w => t.includes(w)).length;
      if (n > hits) { best = cat; hits = n; }
    }
    return best;
  }

  function joinAr(items) {
    if (items.length <= 1) return items.join("");
    return items.slice(0, -1).join("، ") + " و" + items[items.length - 1];
  }
  function joinEn(items) {
    if (items.length <= 1) return items.join("");
    return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
  }

  // ------------------------------------------------------------ fields
  function descriptor(el) {
    const parts = [el.type, el.name, el.id, el.placeholder, el.getAttribute("autocomplete"),
      el.getAttribute("aria-label"), el.getAttribute("inputmode")];
    if (el.labels) for (const l of el.labels) parts.push(l.textContent);
    const lab = el.closest && el.closest("label");
    if (lab) parts.push(lab.textContent);
    return parts.filter(Boolean).join(" ").toLowerCase();
  }

  function classifyField(el) {
    const t = (el.type || "").toLowerCase();
    if (["hidden", "submit", "button", "checkbox", "radio", "image", "reset", "file", "range", "color"].includes(t)) return null;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    const d = descriptor(el);
    if (t === "password" || /current-password|new-password/.test(ac)) return "password";
    if (ac === "one-time-code" || /\botp\b|one.?time|verification code|رمز التحقق|رمز التأكيد|الرمز المرسل|كود/.test(d)) return "otp";
    if (/cc-csc|\bcvv\b|\bcvc\b|security code|رمز الأمان/.test(ac + " " + d)) return "cvv";
    if (/cc-number|cc-exp|card.?number|cardnumber|رقم البطاقة|بطاقة/.test(ac + " " + d)) return "card";
    if (/emirates.?id|national.?id|رقم الهوية|الهوية الإماراتية/.test(d)) return "id_number";
    if (t === "email" || /e-?mail|البريد/.test(d)) return "email";
    if (/track|tracking|رقم الشحنة|رقم التتبع|awb/.test(d)) return "tracking";
    return "other";
  }

  function isVisible(el) {
    if (!el.getBoundingClientRect) return true;
    const r = el.getBoundingClientRect();
    const s = root.getComputedStyle ? root.getComputedStyle(el) : null;
    if (s && (s.display === "none" || s.visibility === "hidden")) return false;
    return r.width > 0 || r.height > 0;
  }

  function scanFields(doc) {
    const kinds = new Set();
    const sensitiveEls = [];
    for (const el of doc.querySelectorAll("input, textarea, select")) {
      if (!isVisible(el)) continue;
      const k = classifyField(el);
      if (!k) continue;
      kinds.add(k);
      if (SENSITIVE.includes(k)) sensitiveEls.push(el);
    }
    if (kinds.has("password") && kinds.has("email")) { kinds.add("email_password"); kinds.delete("password"); }
    return { kinds, sensitiveEls };
  }

  // ------------------------------------------------------------- brand
  function pageText(doc) {
    const bits = [doc.title || ""];
    doc.querySelectorAll('meta[property="og:site_name"], meta[name="application-name"]').forEach(m => bits.push(m.content || ""));
    doc.querySelectorAll("h1, h2, h3, header, img[alt]").forEach(e => bits.push(e.alt || e.textContent || ""));
    bits.push(((doc.body && doc.body.innerText) || "").slice(0, 6000));
    return bits.join(" \n ").toLowerCase();
  }

  function countAlias(text, alias) {
    const a = alias.toLowerCase();
    if (/^[a-z0-9 &.\-]+$/.test(a)) {   // Latin: whole words only, so "du" does not match "during"
      const re = new RegExp("(^|[^a-z0-9])" + a.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?=$|[^a-z0-9])", "g");
      return (text.match(re) || []).length;
    }
    return text.split(a).length - 1;
  }

  function hostIn(host, domains) {
    host = host.replace(/^www\./, "");
    return domains.some(d => host === d || host.endsWith("." + d));
  }

  function detectBrand(doc, host, brands) {
    const title = (doc.title || "").toLowerCase();
    const text = pageText(doc);
    let claimed = null, bestScore = 0;
    for (const b of brands) {
      let n = 0, inTitle = false;
      for (const a of b.aliases) {
        n += countAlias(text, a);
        if (countAlias(title, a) > 0) inTitle = true;
      }
      const score = n + (inTitle ? 3 : 0);
      if ((inTitle || n >= 2) && score > bestScore) { claimed = b; bestScore = score; }
    }
    const officialFor = brands.find(b => hostIn(host, b.domains)) || null;
    return { claimed, officialFor };
  }

  // ----------------------------------------------------------- analyse
  /**
   * @param doc      the page document
   * @param loc      the page location
   * @param ctx      { brands: [...], journey: {query, category} | null, known: {...} | null }
   * @returns        { level: "high"|"medium"|"none", score, signals[], brand, category, requested[], host }
   */
  function analyze(doc, loc, ctx) {
    const host = (loc.hostname || "").toLowerCase();
    const isLocal = /^(localhost|127\.|0\.0\.0\.0|\[::1\]|10\.|192\.168\.)/.test(host);
    const { kinds, sensitiveEls } = scanFields(doc);
    const requested = SENSITIVE.filter(k => kinds.has(k));
    const brands = (ctx && ctx.brands) || [];
    const { claimed, officialFor } = detectBrand(doc, host, brands);
    const journey = (ctx && ctx.journey) || null;
    const known = ctx && ctx.known && ctx.known.known ? ctx.known : null;
    const signals = [];

    if (known) {
      signals.push({ code: "known_threat", w: 100,
        ar: `هذا الرابط رُصد ${known.ago_ar} ${known.source_ar} (القضية #${known.case_id}).`,
        en: `This link was seen ${known.ago_en} ${known.source_en}.`,
        share: `الرابط معروف مسبقاً في المخزن المشترك (القضية #${known.case_id}).` });
    }

    const mismatch = !!claimed && !hostIn(host, claimed.domains);
    if (mismatch) {
      signals.push({ code: "brand_mismatch", w: 40,
        ar: `تدّعي الصفحة أنها «${claimed.name_ar}»، لكن نطاقها (${host}) ليس من نطاقاتها المعتمدة.`,
        en: `The page claims to be ${claimed.name_en}, but its domain (${host}) is not one of its official domains.`,
        share: `تدّعي أنها «${claimed.name_ar}» على نطاق غير معتمد.` });
    }

    const category = (claimed && claimed.category) || (journey && journey.category) || null;
    const unexpected = category ? requested.filter(k => !(EXPECTED[category] || []).includes(k)) : [];
    if (unexpected.length && requested.length) {
      signals.push({ code: "unexpected_request", w: 35,
        ar: `${PLURAL_AR[category]} لا تطلب عادةً ${joinAr(unexpected.map(k => ITEM_AR[k]))}.`,
        en: `${PLURAL_EN[category]} do not usually ask for ${joinEn(unexpected.map(k => ITEM_EN[k]))}.`,
        share: `تطلب ${joinAr(unexpected.map(k => ITEM_AR[k]))} وهذا غير معتاد في ${SERVICE_AR[category]}.` });
    }

    if (journey && journey.category && requested.length) {
      const offJourney = requested.filter(k => !(EXPECTED[journey.category] || []).includes(k));
      if (offJourney.length) {
        signals.push({ code: "journey_shift", w: 25,
          ar: `وصلت إلى هذه الصفحة بعد بحثك عن «${journey.query}»، لكنها تطلب ${joinAr(offJourney.map(k => ITEM_AR[k]))}.`,
          en: `You arrived here after searching for "${journey.query}", but the page asks for ${joinEn(offJourney.map(k => ITEM_EN[k]))}.`,
          share: `وصل المستخدم بعد بحث عن ${SERVICE_AR[journey.category]}، ثم طُلب منه ${joinAr(offJourney.map(k => ITEM_AR[k]))}.` });
      }
    }

    if (loc.protocol === "http:" && requested.length && !isLocal) {
      signals.push({ code: "insecure", w: 20,
        ar: "الصفحة تطلب بيانات حساسة عبر اتصال غير مشفّر.",
        en: "The page asks for sensitive data over an unencrypted connection.",
        share: "تطلب بيانات حساسة عبر http." });
    }

    const score = signals.reduce((a, s) => a + s.w, 0);
    const has = c => signals.some(s => s.code === c);
    const onOfficial = !!officialFor && (!claimed || officialFor.id === claimed.id);
    let level = "none";
    if (has("known_threat")) level = "high";
    else if (!onOfficial && requested.length && (
      (has("brand_mismatch") && (has("unexpected_request") || has("journey_shift") || requested.length)) ||
      (has("unexpected_request") && has("journey_shift")))) level = "high";
    else if (!onOfficial && requested.length && score >= 35) level = "medium";

    return {
      level, score, signals, host, category, requested,
      brand: claimed ? claimed.name_ar : "", brand_en: claimed ? claimed.name_en : "",
      official: onOfficial ? officialFor.name_ar : "",
      _sensitiveEls: sensitiveEls,
    };
  }

  root.HarisAnalyzer = { analyze, categoryOfText, classifyField, scanFields, detectBrand, ITEM_AR };
})(typeof window !== "undefined" ? window : globalThis);
