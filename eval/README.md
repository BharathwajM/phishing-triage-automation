# Accuracy test on public email corpora

The samples in this repo are synthetic and were written alongside the rules, so passing them says little about real email. This folder measures the tool on public corpora of real phishing and real legitimate mail.

## Data

| Corpus | Class | Messages | Split | Source and licence |
|---|---|---|---|---|
| `phishing-2024` | Phishing | 403 | Dev | [Nazario phishing corpus](https://monkey.org/~jose/phishing/), CC BY 4.0 |
| `phishing-2025` | Phishing | 481 | Test | Nazario phishing corpus, CC BY 4.0 |
| `20030228_easy_ham` | Legitimate | 2,500 | Dev | [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/), copyright stays with the original senders |
| `20030228_hard_ham` | Legitimate | 250 | Test | SpamAssassin public corpus |

None of the email is stored in this repo. `evaluate.py` downloads the four files, checks each SHA-256 against the version used here, and reads messages straight out of the mbox files and tar archives. Nothing is extracted or opened, and live enrichment is never called. Only aggregate counts are written out.

## Method

I set up the split before changing any rules:

- **Dev set** (2024 phishing and easy_ham). I studied its misses and false alarms and changed the rules to fix them.
- **Test set** (2025 phishing and hard_ham). This is a later year of phishing and the harder legitimate mail. I ran it once, after tuning was finished.

A message counts as **flagged** if the verdict is SUSPICIOUS or MALICIOUS.

## Results

| Set | Phishing flagged | Legitimate flagged (false alarms) |
|---|---|---|
| Dev, before | 22.6% (91 of 403) | 18.2% (455 of 2,500) |
| Dev, after | **41.9%** (169 of 403) | **0.3%** (8 of 2,500) |
| Test, before | 19.1% (92 of 481) | 20.4% (51 of 250) |
| Test, after | **29.3%** (141 of 481) | **15.6%** (39 of 250) |

[`results-baseline.json`](results-baseline.json) has the full output before the changes and [`results.json`](results.json) has the output after. Both include verdict counts per corpus and how often each indicator fired.

## What the dev set showed, and what changed

**False alarms.** 452 of the 455 dev false alarms included the Return-Path warning and 442 included the Reply-To warning. Both scored medium, so together they reached SUSPICIOUS. Mailing lists use a separate bounce address and set Reply-To to the list, so this pair turns up all the time in normal mail.
- The Return-Path warning is now low.
- The Reply-To warning is low unless replies go to a free webmail address such as Gmail.

**Brand-name bugs.** The brand check used a plain substring match. That meant "ups" matched `groups.google.com`, "ato" matched `usatoday.com`, and 16 dev phishing emails from senders named "Server Administrator" or similar were reported as impersonating the ATO. Those were right for the wrong reason.
- Short brand names (under 5 letters) must now be a whole word.
- Longer names only need to start a word, so `microsoftonline-verify.com` still matches.
- A link with a brand word in its domain used to be reported twice, once as a look-alike domain and once as a brand in an unrelated domain. It is now reported once.

**Misses.** Most missed dev phishing used one of two delivery methods the tool did not check for:
- **HTML attachments** (`.html`, `.shtml`, `.svg` and similar). They open a fake login page locally or smuggle a file past the mail filter. 30 messages in the dev set had one. They are now a high-severity finding.
- **Hard-to-take-down hosting**: IPFS gateways (`ipfs.io`, `dweb.link`, `cloudflare-ipfs.com`) and free developer hosting (`r2.dev`, `glitch.me`, `vercel.app`, `workers.dev`, `pages.dev`). These are now high and medium findings, counted once per platform. The lists also include six well-known platforms that do not appear in the dev set, such as `netlify.app` and `firebaseapp.com`. I added those from general threat reporting, not from this data.

**Threshold.** After those changes, the largest group of dev misses scored exactly 32, which is one high-severity finding on its own. The SUSPICIOUS line was 35, so one high finding could never reach it. I lowered the line to 30, so that one high finding is enough to send a message to an analyst. On the dev set this added 45 phishing detections and 1 false alarm.

**Encoded and disguised sender names.** While writing this up I found that sender names were checked in their raw encoded form (`=?UTF-8?Q?Ch=D0=B0se_B=D0=B0nk...`), so the brand check never saw them. Decoding them showed a pattern: dev phishing sent through Google Drive and DocuSign's own sharing features, with names like "Chаse Bаnk (via Google Drive)" where the "а" is Cyrillic.
- Names and subjects are now decoded.
- Look-alike Cyrillic and Greek letters, full-width letters and invisible characters are mapped to plain Latin before the brand check.
- A brand that only appears after that mapping is a new high-severity finding.
- Every brand in the name is checked, not just the first. In "Chase Bank (via Google Drive)" sent from google.com, Google is genuine but Chase is not.

This took the dev set from 39.5% to 41.9% with no new false alarms. Some of these names still get through, such as "WeIIsFargo" spelled with a capital I instead of an l, and "Bank of America" written with spaces.

## Limitations

- **Test-set false alarms.** On the test set, 30 of the 39 false alarms were caused by the brand-in-domain check. They came from legitimate senders with a brand word in their own domain: an Apple newsletter (`applecore.lockergnome.com`), an Outlook add-in vendor (`outlook.4team.biz`) and `outlooksecure.com`. I have not changed the rule after seeing this, because that would make the test set no longer held out. An allow-list of known senders would be the usual fix in a real deployment.
- **The legitimate mail is from 2002 and 2003.** It has almost no HTML marketing mail, link tracking or modern bulk-mail services, so the false-alarm rate on a 2026 inbox would be different. I could not find a public corpus of recent legitimate business email with a licence that allows this kind of use.
- **Many phishing emails give the rules nothing to score.** Of the 340 test phishing messages that were not flagged, 124 matched no rule at all. These are usually short lures with an ordinary-looking link, or text-only scams. Catching them needs URL reputation (the `--enrich` option, not used here) or a content model.
- **The test set is not perfectly blind.** My first look at misses and false alarms, before I set up the split, covered all four corpora together. Every rule change above is backed by dev-set examples. I also took out two hosting domains (`sslip.io`, `nip.io`) that I had noticed in that first look but that do not appear in the dev set. Even so, I had already seen some of the test data.
- **The test set has been run twice.** The second run was after the encoded-name fix described above, which came from dev-set examples. The test numbers did not change.

## Reproduce

```bash
python eval/evaluate.py --download --data corpus/   # about 37 MB, verified by SHA-256
python eval/evaluate.py --data corpus/
```

`corpus/` is in `.gitignore`. The run prints the dev, test and combined numbers and writes `eval/results.json`.
