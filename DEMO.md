# Live pitch and demo (5 minutes + 5 minutes Q&A)

The guide gives each team 10 minutes: about 1 minute to state the problem and the solution, about 3 minutes of demo, and questions. Timing is strict.

## Before the slot (the night before and again in the morning)

1. `python -m unittest discover -s tests` must end with `OK`.
2. `python seed_demo.py --reset`, then `python bot.py` (or `python -m altum.dashboard` if Telegram is not used).
3. Chrome: Haris extension loaded; tabs open on `http://127.0.0.1:8080/scan`, `http://127.0.0.1:8080/` and `http://127.0.0.1:8080/demo/`.
4. Phone 1 ("scammer"): chat with the bot open, `/reset` sent. Phone 2 ("police"): `/police <PIN>` sent.
5. Check the venue Wi-Fi: online checks (redirects, domain age) need internet. Without it, untick "online" on the scan page; the URL-only results still stand.

## 0:00 – 1:00 · Problem and solution (slides 1–3)

"Scams in the UAE arrive as links: fake TAMM fines, fake UAE PASS, fake bank and courier pages. Protection today depends on the victim suspecting the link. Haris Scanner scores any link with reasons and police-ready evidence, Haris protects people while they browse, and Al-Tu'm catches new links straight from scammers' chats."

## 1:00 – 2:15 · Haris Scanner (criteria 1, 3, 4)

1. On `/scan`, click **افحص** with the five pre-filled links → three phishing, two safe (the official TAMM page and a news article about UAE PASS fines).
   **Say:** "Official TAMM and a news article are not flagged. False positives on real government sites are what the criteria warn about."
2. Point at the reasons under `tamm-fines-pay.top`: the TAMM name on a domain it does not own, government branding outside `.gov.ae`, lure words, a risky extension, each in Arabic and English.
3. Click **📄 حزمة الأدلة** → the evidence report: redirect chain, registrar and abuse e-mail, hosting, TLS, page fingerprint and UTC time. **Say:** "Print, or export the takedown CSV."

## 2:15 – 3:00 · Early detection (criterion 2)

In a terminal:
```
python -m altum.scanner watch --feed eval/nrd_sample.txt
python -m altum.scanner listings eval/listings_sample.csv
```
**Say:** "Every day we filter newly registered domains for imitations of UAE brands, before the first SMS is sent. And Maps listings: an 'ADCB Customer Care' on a mobile number is flagged."

## 3:00 – 4:30 · Haris in the browser, and the integration moment (criteria 2 and 4)

1. Phone 1 sends: `عزيزي العميل، شحنتك محتجزة. أكّد بياناتك هنا: http://127.0.0.1:8080/demo/falcon-track`
   → the bait replies, and the link is extracted (phone 2 gets the alert).
2. Open the same link in Chrome → the Haris warning shows: "This link was seen less than a minute ago in a scam conversation caught by Al-Tu'm", the fake brand and the unofficial domain, and "shipping companies do not ask for your email password".
3. Dashboard → the Haris case and the Al-Tu'm case are linked in one network.
   **Say:** "One link caught in one chat protected every user within seconds."

## 4:30 – 5:00 · Close (last slides)

Honest limitations (our own test sets, a brand list to confirm with each organisation) and the route to a police pilot in three steps.

## Backup plan

| Problem | Fix |
|---|---|
| No internet | Untick "online" on `/scan`; the URL-only results and the evidence report still work |
| Telegram down | `python cli_chat.py --offline` and paste the same message |
| Haris warning missing | reload the page; if "continue" was pressed earlier, restart Chrome |
| Laptop failure | play the one-minute demo video |

## Likely questions

- **How accurate is it?** On our labelled sets: precision 1.00, recall 0.93–0.97 (strict), and no legitimate site flagged. The sets are our own, so we want the police's data to re-tune the weights.
- **Why rules, not a model?** Every score must be explainable as evidence; rules work from day one without training data; the same features can train a model later.
- **Evasion?** We follow HTTP, meta and JavaScript redirects and shorteners, compare what a user sees with what Googlebot sees (cloaking), decode punycode look-alikes, and check the landing domain as well as the link.
- **Privacy?** The extension reads the type of each field, never its value, and never sends the search text.
- **Scale?** Scans are stateless and run in parallel; RDAP and DNS are free and keyless.
