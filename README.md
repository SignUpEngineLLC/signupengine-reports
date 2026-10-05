# SignUpEngine Reports

Client reports published with GitHub Pages at https://signupenginellc.github.io/signupengine-reports/

## ⚠ This repo and its site are public

Only publish reports that contain no personal data (names, emails, addresses, individual orders).
`robots.txt` and the `noindex` meta tags keep pages out of search engines, but anyone with a link can
open an unprotected report.

## Layout

```
reports.json                          every client and report; "protected": true locks a report
build.py                              builds the site: uv run build.py
<client>/index.html                   the client's report list (generated, don't edit)
<client>/<yyyy-mm>-<slug>/index.html  one report (generated, don't edit)

_private/                             gitignored, stays on this PC only
  sources/<client>/<slug>.html        the original report HTML
  passwords.json                      one password per client: {"<client>": {"password", "salt"}}
```

## Adding a report

1. Save the original HTML as `_private/sources/<client>/<yyyy-mm>-<slug>.html`.
2. Add the report to that client's `reports` list in `reports.json`. For a new client, add the client too.
3. Run `uv run build.py`, then commit and push to `main`. Pages redeploys in a minute or two.

### Page prototypes

Prototypes work the same way, with `"kind": "prototype"` on the entry so the client page lists them
under their own heading. Each version gets its own folder, so links to earlier versions keep working:
`_private/sources/<client>/<page>/v27.html` → `<client>/<page>/v27/`.

## Password protection

When a report is set to `"protected": true`, `build.py` encrypts it with AES-256-GCM. The key comes
from the client's password (PBKDF2-SHA256, 600,000 iterations). Only the password page and the
encrypted data are published; the readable report never reaches the repo. The page decrypts the
report in the browser. Every protected report for a client uses the same password, and "Remember on
this device" saves the key so that client's other reports open without asking again.

- The build refuses to run if a protected report's client has no password, and it checks that no
  report text appears in the locked output.
- Changing a client's password (or its `salt`) and rebuilding locks every one of that client's
  reports with the new password. A copy someone downloaded earlier can still be opened with the old one.
- Keep `_private/` backed up. If you lose `passwords.json`, a protected report can only be recovered
  from the live site if someone remembers the password.
- To lock a report that has already been published unprotected, you also have to purge its plain
  version from the git history. Protection only hides what comes after it.

## Clients

- `nyjtl/`: NYJTL
- `usta-midwest/`: USTA Midwest Tennis Center
- `jtcc/`: JTCC (password protected prototypes)
