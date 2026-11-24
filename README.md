# Al-Tu'm × Haris — الطُّعم × حارس

**SCAMSHIELD AI Hackathon · 42 Abu Dhabi × Abu Dhabi Police · November 2026**

> يسبق الخداع… ويصطاد المحتال. منظومة ذكاء اصطناعي تكشف روابط ومواقع الاحتيال قبل أن تصل للضحية، وتشرح كل حكم بالعربية والإنجليزية، وتُخرج أدلة جاهزة للشرطة.

**Team** · Majed Alzaabi (team leader, alzaabimajed@gmail.com) · Ahmed Abouelnasr (anaahmed322005@gmail.com) · Abubaker Alamoudi (uaealamoudi@gmail.com) · Ragab Abdelmeguid (Ragabelsaadany2@gmail.com)

**Repository** · https://github.com/ragabelsaadany2-ai/altum-haris

---

## 1. The problem

Scams in the UAE arrive as links: a fake TAMM page to "pay a traffic fine", a fake UAE PASS login, a fake bank "account suspended" page, a fake Aramex/Emirates Post "redelivery fee", a fake bank helpline on Google Maps. Today:

- protection depends on the victim suspecting the link and pasting it into a checker, and people who don't suspect don't check;
- scam domains are registered, used for a few days, and replaced, so block lists are always late;
- when a link is reported, the evidence police need (where it is hosted, who registered it, when, what it looked like) is collected by hand, if at all.

## 2. Our solution

One system with three parts that share one intelligence store:

| Part | What it does |
|---|---|
| **Haris Scanner** (`altum/scanner/`) | Scores any URL 0–100 (phishing / suspicious / safe) with **reasons in Arabic and English**. Follows redirects and shorteners, detects cloaking, reads the page (what brand it claims, what it asks for, where the form sends data), checks domain age, hosting and TLS, and produces a **police evidence package** and a **takedown CSV**. Also hunts **look-alike domains** before they are used and checks **Maps/search listings** for fake helplines. |
| **Haris browser extension** (`haris-extension/`) | Runs while people browse. Understands the journey (searched "track shipment", landed on a page claiming a courier, page asks for the email password) and warns **before** the user types anything. Never reads what the user types. |
| **Al-Tu'm** (`bot.py`, `altum/engine.py`) | A Telegram bait: an AI persona answers scammers, keeps them talking and extracts their IBANs, phone numbers and **links**. Every link it extracts goes into the shared store, so Haris blocks it for everyone within seconds. |

All three feed the **police dashboard** (`http://127.0.0.1:8080`), where cases that share a link, IBAN, phone, **hosting IP or name server** are linked into one network.

### How it maps to the judging criteria

| Criterion | Weight | Where it is in this repo |
|---|---|---|
| Detection accuracy | 30% | `altum/scanner/` (lexical, content, infrastructure and intelligence signals). Official domains, `.gov.ae` and popular sites are never flagged on look-alike signals. Evasion: redirect chains (HTTP, meta-refresh, JavaScript), shorteners, cloaking (we fetch as a user and as Googlebot and compare). Measured results in §5. |
| Early detection and coverage | 25% | `watch`: generates typo, homoglyph, combo and other-TLD look-alikes of every UAE brand and checks which are registered and how new they are (DNS + RDAP), or filters a daily newly-registered-domains feed. `listings`: checks Maps/search/ad listings for brand names with unofficial websites and helplines on mobile or foreign numbers. Al-Tu'm catches links in scam chats before anyone reports them. |
| Explainability and actionability | 20% | Every flag has weighted reasons (Arabic + English) with the evidence value. `--evidence` writes per URL: `report.json` (UTC timestamps, redirect chain, RDAP registration + registrar abuse e-mail, hosting network + abuse e-mail, IPs, TLS), `page.html` + SHA-256, `screenshot.png`, a printable bilingual `report.html`, and one row in `takedown.csv`. |
| UAE relevance and innovation | 15% | A reference of 35 brands (`haris-extension/brands.json`): UAE banks, TAMM, UAE PASS, ICP, MOI, police, RTA, Salik, couriers, telcos and the most-phished global brands. Rules for government impersonation outside `.gov.ae`. Arabic and bilingual page analysis. Novel: links scam domains as a **network** (shared hosting, name servers, IBANs, phones), feeds links captured by an **AI bait** into browser protection, and journey-aware warnings. |
| Feasibility and presentation | 10% | Pure Python standard library for the scanner (no paid APIs, no keys). Runs on one laptop, scales horizontally (stateless scans, thread pool). Honest limitations in §7. |

## 3. Technical choices, tools, APIs and data

- **Language:** Python 3.10+ for everything server-side. The scanner, dashboard and evidence package use **only the standard library** (`urllib`, `ssl`, `socket`, `sqlite3`, `http.server`).
- **Detection model:** a transparent, weighted rule engine (about 30 signals). We chose rules over a black-box model so every score can be explained to a judge or a court, and so it works without training data. The score is `100 × (1 − e^(−Σw/45))`, with thresholds phishing ≥ 60 and suspicious ≥ 40.
- **Signals:** URL (IP host, punycode/IDN look-alikes including Cyrillic/Greek homoglyphs (Arabic-script domains such as `.امارات` are not penalised), pages on publish-anything platforms such as `sites.google.com` judged on their own path rather than the platform's reputation, `@`, shorteners, free hosting, risky TLDs, deep subdomains, lure words, brand token in a foreign domain, typosquatting by edit distance and homoglyph skeletons, government names outside `.gov.ae`, WordPress-hosted kits); page (brand claimed in title/text, sensitive fields such as password, OTP, card, CVV and Emirates ID, form posting off-site, logos loaded from the real brand's site, obfuscated JavaScript, unofficial phone numbers); infrastructure (domain age, certificate age); intelligence (link already seen in an Al-Tu'm chat or reported by a Haris user).
- **APIs:** **RDAP** via `https://rdap.org` (free, no key) for registration date, registrar and abuse contacts; RDAP for IP ownership; DNS and TLS directly. No WHOIS scraping, no paid threat feeds.
- **Data:** `haris-extension/brands.json` (official domains, URL tokens and helplines; **verify with each organisation before real use**); `eval/urls_labeled.csv` (144 labelled URLs) and `eval/holdout.csv` (60, written after the rules were tuned); `eval/listings_sample.csv`; `eval/nrd_sample.txt`.
- **Al-Tu'm:** `python-telegram-bot`; optional LLM through any OpenAI-compatible API (it falls back to scripted personas offline); IBAN mod-97 validation; SQLite.
- **Browser extension:** Chrome Manifest V3, plain JavaScript, Shadow-DOM warning overlay.
- **Screenshots:** Playwright + Chromium (optional; everything else works without it).

## 4. How to build and run

```bash
git clone https://github.com/ragabelsaadany2-ai/altum-haris && cd altum-haris
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                          # Telegram library (only needed for bot.py)
pip install playwright && playwright install chromium    # optional, for evidence screenshots
```

**Scan links** (this is the command for a test set):

```bash
python -m altum.scanner scan https://tamm-fines-pay.top/login https://uaepass.ae/
python -m altum.scanner scan --input urls.txt --out results.csv --json results.json --evidence evidence/
#   urls.txt: one URL per line, or a CSV with a "url" column
#   results.csv columns: url, label (phishing|suspicious|safe), is_phishing (1/0), score, impersonates, final_url, reasons_en, reasons_ar
#   evidence/: one folder per flagged URL + takedown.csv
#   --offline   URL-only checks (no network)      --record   also add findings to the police map
```

**Early detection:**

```bash
python -m altum.scanner watch --out lookalikes.csv                  # generate look-alikes of all UAE brands, keep the registered ones
python -m altum.scanner watch --brand tamm --brand uaepass --out tamm.csv
python -m altum.scanner watch --feed nrd.txt --out flagged_new.csv  # filter a newly-registered-domains feed
python -m altum.scanner listings eval/listings_sample.csv --out listings_checked.csv
```

**Measure accuracy on a labelled file** (`url,label` with label `phishing` or `legit`):

```bash
python -m altum.scanner evaluate eval/urls_labeled.csv            # URL-only
python -m altum.scanner evaluate my_set.csv --online              # with page, redirect and domain-age checks
```

**Dashboard, scan page and API:**

```bash
python -m altum.dashboard          # http://127.0.0.1:8080  (police map)  ·  http://127.0.0.1:8080/scan  (scan page)
curl "http://127.0.0.1:8080/api/scan?url=https://salik-ae-topup.shop"
curl -X POST http://127.0.0.1:8080/api/scan -H "Content-Type: application/json" -d '{"urls":["https://adcb-secure-update.xyz/login"]}'
curl "http://127.0.0.1:8080/evidence?url=https://salik-ae-topup.shop" > evidence.html
```

**Browser extension:** open `chrome://extensions`, turn on Developer mode, choose **Load unpacked**, and pick the `haris-extension` folder. Demo pages (fictional brand): `http://127.0.0.1:8080/demo/`.

**Al-Tu'm (Telegram bait):** copy `.env.example` to `.env`, set `TELEGRAM_BOT_TOKEN` (from @BotFather), then:

```bash
python seed_demo.py --reset && python bot.py      # or, without Telegram:  python cli_chat.py --offline
```

**Tests:** `python -m unittest discover -s tests` runs 24 tests. The online tests use a local fake web; add `127.0.0.1 short.test tamm-fines.test collector.test news.test bounce.test` to your hosts file to run them (otherwise they are skipped).

## 5. Results

URL-only checks (`--offline`), no network:

| Set | URLs | Precision | Recall (strict: "phishing" only) | Recall (phishing + suspicious) | False alarms on legitimate sites |
|---|---|---|---|---|---|
| Development `eval/urls_labeled.csv` | 70 legit · 74 phishing | 1.00 | 0.93 | 0.99 | 0 |
| Held-out `eval/holdout.csv` | 30 legit · 30 phishing | 1.00 | 0.97 | 1.00 | 0 |

The legitimate URLs are real official and popular sites, including hard cases: bank login pages, `.gov.ae` payment pages, and news articles about TAMM, UAE PASS and fines. The phishing URLs follow documented scam patterns but are **constructed by us**, so these numbers show the rules work as designed, not real-world accuracy. Online checks (redirects, page content, domain age, cloaking) add further signals; they are tested against a local fake web in `tests/`.

## 6. Repository map

```
altum/scanner/        Haris Scanner: lexical.py, content.py, infra.py, engine.py, evidence.py, watch.py, listings.py, record.py, __main__.py (CLI)
altum/dashboard.*     police dashboard + /scan page + API          altum/haris.py   shared-intel API for the extension
altum/engine.py ...   Al-Tu'm bait engine (personas, extraction, IBAN validation, store, reports)
haris-extension/      Chrome extension + brands.json (shared brand reference)
bot.py  cli_chat.py  seed_demo.py                                   Al-Tu'm entry points
eval/                 labelled URL sets, sample listings and newly-registered-domains feed
tests/                24 automated tests (+ local fake web)
DEMO.md               the 3-minute live demo script
```

## 7. Limitations (honest)

- Accuracy figures come from our own labelled sets; the real hidden test set will be harder. The rule weights are ready to be re-tuned (or replaced by a trained model) on police-labelled data.
- The brand reference was compiled by the team; every official domain and helpline must be confirmed by the organisations before a pilot.
- Online checks depend on the target site responding; heavily scripted pages that build their form only in JavaScript are analysed by the browser extension, not by the server-side fetch.
- RDAP does not return a creation date for every TLD (some ccTLDs); the domain-age signal is then skipped, not guessed.
- Maps coverage works on listing data (name, phone, website) provided by an export or API; scraping Google Maps directly is not included.
- Al-Tu'm runs on Telegram in this prototype; production would use WhatsApp Business numbers operated under police authority.

## 8. Route to a police pilot

1. **Week 1–2:** the police confirm `brands.json` (official domains and helplines) and share a labelled sample of reported scam URLs; we re-tune the weights and publish precision and recall on it.
2. **Week 3–6:** run `watch` daily on a newly-registered-domains feed, and run the scanner on links reported by citizens; analysts review the evidence packages and send takedowns from `takedown.csv`.
3. **Month 2–3:** roll the Haris extension out to a pilot group, add the "forward to Al-Tu'm" button to the police app, and move the store to a managed database.
