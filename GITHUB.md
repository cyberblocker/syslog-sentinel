# Publish this as a CyberBlocker project

Suggested repository: **syslog-sentinel**

Description: Centralized TCP/UDP syslog lab with SSH detection, collection-gap checks, and searchable evidence reports.

## Publish using Git

1. Run the lab yourself and review the sample investigation.
2. Sign into GitHub as `cyberblocker`.
3. Create a new repository named `syslog-sentinel`. Choose public if you want recruiters to view it. Leave automatic README, license, and gitignore creation unchecked because these files already exist here.
4. Install Git if needed, then open a terminal inside this extracted project folder.
5. Run each command:

   ```bash
   git init
   git branch -M main
   git add .
   git status
   git commit -m "Add centralized syslog collection and detection lab"
   git remote add origin https://github.com/cyberblocker/syslog-sentinel.git
   git push -u origin main
   ```

Before committing, inspect `git status`: the real `data/` and `reports/` directories should be excluded. Only the explicitly synthetic sample report in `examples/` is included. GitHub may open a browser sign-in. If Git asks for name/email, configure the identity you want on your commits; use your GitHub-provided noreply address if desired.

The commands assume a new empty repository. If that name already exists, pick another name and update the remote URL. Nothing has been published on your behalf.

## Screenshots to add

Save your own screenshots in `docs/screenshots/`:

| Filename | Capture | What it proves |
|---|---|---|
| `01-collector.png` | Collector listening and second terminal running demo | Working ingestion workflow |
| `02-investigation.png` | Report showing nine events and two findings | Correlation results |
| `03-coverage-gap.png` | Expected-source table with missing db-01 | Visibility into collection gaps |
| `04-evidence-search.png` | Search results for the demo source IP | Evidence review |
| `05-real-client.png` | Test event from a separate Linux VM | Real forwarding beyond the simulator |

Keep usernames, unrelated logs, tokens, and private infrastructure details out of screenshots. Add the following to README after creating the actual screenshot:

```markdown
## Demo
![Syslog Sentinel investigation report](docs/screenshots/02-investigation.png)
```

## Make it your project

Add a short `docs/WHAT-I-LEARNED.md` describing what you ran, a problem you fixed, and one improvement you implemented. Replace the sample investigation with your own observations. Explain assistance honestly and be able to walk through the code and design decisions.

Suggested topics: `syslog`, `python`, `networking`, `blue-team`, `homelab`, `detection-engineering`.

Pin the repository on your profile. GitHub hosts the code and documentation; GitHub Pages does not run a TCP/UDP syslog server. Run the collector locally or on your own lab VM.

## Interview talking points

- Why receipt time is used instead of trusting every sender's clock.
- Why host, username, and source IP are part of the correlation key.
- What TCP improves and why it still does not prove durable application storage.
- Why an expected device going quiet deserves investigation.
- Which production controls are deliberately outside this small lab.
