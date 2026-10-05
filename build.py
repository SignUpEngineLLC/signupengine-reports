# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
"""Build the published site from _private/sources/ and reports.json.

    uv run build.py

For every report listed in reports.json:
  _private/sources/<client>/<slug>.html  ->  <client>/<slug>/index.html
Unprotected reports are copied with a noindex tag added. Protected reports are
AES-256-GCM encrypted with a key derived from the client's password
(_private/passwords.json, PBKDF2-SHA256), so only the locked page and ciphertext
are ever published. Also regenerates each <client>/index.html report list.

_private/ is gitignored: it never leaves this PC.
"""

import base64
import html
import json
import re
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "_private"
SOURCES = PRIVATE / "sources"
PASSWORDS = PRIVATE / "passwords.json"
ITERATIONS = 600_000
NOINDEX = '<meta name="robots" content="noindex, nofollow">'
LOCK_MARKER = "<!-- signupengine-reports:locked -->"


def add_noindex(page: str) -> str:
    if 'name="robots"' in page:
        return page
    anchor = r"(<meta charset[^>]*>)" if re.search(r"<meta charset", page, re.I) else r"(<head[^>]*>)"
    return re.sub(anchor, r"\1\n" + NOINDEX, page, count=1, flags=re.I)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def lock_page(page: str, client_id: str, client_name: str, title: str, password: str, salt: bytes) -> str:
    iv = secrets.token_bytes(12)
    ct = AESGCM(derive_key(password, salt)).encrypt(iv, page.encode("utf-8"), None)
    payload = json.dumps({"c": client_id, "s": b64(salt), "i": b64(iv), "n": ITERATIONS, "d": b64(ct)})
    return (
        LOCK_TEMPLATE.replace("{{MARKER}}", LOCK_MARKER)
        .replace("{{NOINDEX}}", NOINDEX)
        .replace("{{CLIENT}}", html.escape(client_name))
        .replace("{{TITLE}}", html.escape(title))
        .replace("{{PAYLOAD}}", payload)
    )


# Optional "kind" on a report entry; each kind gets its own heading on the client page.
KINDS = {"report": "Reports", "prototype": "Page prototypes"}


def client_index(name: str, reports: list[dict]) -> str:
    sections = []
    for kind, heading in KINDS.items():
        items = []
        for r in reports:
            if r.get("kind", "report") != kind:
                continue
            lock = ' <span class="lock" title="Password protected">&#128274;</span>' if r.get("protected") else ""
            note = f'\n      <small>{html.escape(r["note"])}</small>' if r.get("note") else ""
            items.append(
                f'    <li><a href="{html.escape(r["slug"])}/">{html.escape(r["title"])}</a>{lock}{note}</li>'
            )
        if items:
            sections.append(f"  <h2>{heading}</h2>\n  <ul>\n" + "\n".join(items) + "\n  </ul>")
    return CLIENT_INDEX_TEMPLATE.replace("{{NAME}}", html.escape(name)).replace("{{ITEMS}}", "\n".join(sections))


def main() -> int:
    config = json.loads((ROOT / "reports.json").read_text(encoding="utf-8"))
    passwords = json.loads(PASSWORDS.read_text(encoding="utf-8")) if PASSWORDS.exists() else {}
    errors = []

    for client_id, client in config.items():
        for r in client["reports"]:
            src = SOURCES / client_id / f'{r["slug"]}.html'
            out = ROOT / client_id / r["slug"] / "index.html"
            if r.get("kind", "report") not in KINDS:
                errors.append(f"{client_id}/{r['slug']}: unknown kind {r['kind']!r} (use one of {', '.join(KINDS)})")
            if not src.exists():
                errors.append(f"missing source: {src.relative_to(ROOT)}")
                continue
            page = add_noindex(src.read_text(encoding="utf-8"))

            if r.get("protected"):
                entry = passwords.get(client_id)
                if not entry or not entry.get("password"):
                    errors.append(f"{client_id}/{r['slug']} is protected but _private/passwords.json has no password for {client_id!r}")
                    continue
                result = lock_page(page, client_id, client["name"], r["title"], entry["password"], bytes.fromhex(entry["salt"]))
                # Belt and braces: the report's own text must never appear in a locked page.
                body = re.sub(r"<[^>]+>", " ", page.split("<body", 1)[-1])
                probe = max(re.findall(r"[A-Za-z][^<>\n]{40,}", body) or [""], key=len)[:40]
                if LOCK_MARKER not in result or (probe and probe in result):
                    errors.append(f"{client_id}/{r['slug']}: locked output failed the plaintext check, not written")
                    continue
                state = "locked"
            else:
                result = page
                state = "public"

            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(result, encoding="utf-8", newline="\n")
            print(f"  {state:6}  {client_id}/{r['slug']}/")

        (ROOT / client_id / "index.html").write_text(
            client_index(client["name"], client["reports"]), encoding="utf-8", newline="\n"
        )

    # Any page on disk that claims to be locked but isn't listed as protected would be a
    # stale leftover; any listed-protected page without the marker would be a leak.
    for client_id, client in config.items():
        for r in client["reports"]:
            out = ROOT / client_id / r["slug"] / "index.html"
            if r.get("protected") and out.exists() and LOCK_MARKER not in out.read_text(encoding="utf-8"):
                errors.append(f"LEAK RISK: {out.relative_to(ROOT)} is protected but not locked. Do not push.")

    if errors:
        print("\nErrors:", *errors, sep="\n  ", file=sys.stderr)
        return 1
    print("Build OK.")
    return 0


CLIENT_INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{NAME}}</title>
<style>
  body{margin:0;background:#F5F7F5;color:#0F2A33;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif}
  .wrap{max-width:720px;margin:0 auto;padding:48px 16px}
  h1{margin:0 0 4px} .sub{color:#5C7078;margin:0 0 28px}
  h2{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#5C7078;margin:28px 0 6px}
  ul{list-style:none;padding:0;margin:0}
  li{border-top:1px solid #B9D3D9;padding:14px 0}
  a{color:#2E7D8F;font-weight:600;text-decoration:none} a:hover{text-decoration:underline}
  .lock{font-size:.85em;margin-left:4px}
  small{display:block;color:#5C7078;margin-top:2px}
</style>
</head>
<body>
<div class="wrap">
  <h1>{{NAME}}</h1>
  <p class="sub">Prepared by SignUpEngine</p>
{{ITEMS}}
</div>
</body>
</html>
"""

LOCK_TEMPLATE = """<!DOCTYPE html>
{{MARKER}}
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{NOINDEX}}
<title>{{TITLE}}</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:#F5F7F5;color:#0F2A33;
       font-family:"Helvetica Neue",Helvetica,Arial,sans-serif}
  form{width:100%;max-width:380px;background:#fff;border:1px solid #B9D3D9;border-top:3px solid #0F2A33;padding:28px 24px}
  .who{margin:0;color:#5C7078;font-size:13px}
  h1{font-size:20px;margin:6px 0 20px;line-height:1.25}
  label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}
  input[type=password]{width:100%;font:inherit;font-size:16px;padding:10px 12px;border:1px solid #9FB2B8;border-radius:0}
  input[type=password]:focus{outline:2px solid #2E7D8F;outline-offset:1px}
  .row{display:flex;align-items:center;gap:6px;margin:12px 0 18px;font-size:13px;color:#5C7078}
  button{width:100%;font:inherit;font-weight:600;font-size:15px;padding:11px;border:0;background:#2E7D8F;color:#fff;cursor:pointer}
  button:disabled{opacity:.6;cursor:progress}
  .err{color:#A8412F;font-size:13px;min-height:1.2em;margin:10px 0 0}
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <p class="who">Prepared for {{CLIENT}}</p>
  <h1>{{TITLE}}</h1>
  <label for="pw">Password</label>
  <input type="password" id="pw" required autofocus>
  <div class="row"><input type="checkbox" id="rm" checked><label for="rm" style="margin:0;font-weight:400">Remember on this device</label></div>
  <button id="go">View report</button>
  <p class="err" id="err" role="alert"></p>
</form>
<script>
(function(){
  var P = {{PAYLOAD}};
  var KEY = "ser-key-" + P.c;
  function unb64(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); }
  function store(){ try { return window.localStorage; } catch (e) { return null; } }
  async function open(key){
    var buf = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(P.i)}, key, unb64(P.d));
    var page = new TextDecoder().decode(buf);
    document.open(); document.write(page); document.close();
  }
  async function derive(pw){
    var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2", salt:unb64(P.s), iterations:P.n, hash:"SHA-256"},
      base, {name:"AES-GCM", length:256}, true, ["decrypt"]);
  }
  var err = document.getElementById("err"), go = document.getElementById("go");
  if (!window.crypto || !crypto.subtle) { err.textContent = "This browser can't open protected reports. Try an up-to-date Chrome, Edge, Safari or Firefox."; go.disabled = true; return; }
  // Same client password unlocks all of that client's reports, so a remembered key is reused.
  var s = store(), saved = s && s.getItem(KEY);
  if (saved) {
    crypto.subtle.importKey("raw", unb64(saved), "AES-GCM", false, ["decrypt"]).then(open)
      .catch(function(){ try { s.removeItem(KEY); } catch (e) {} });
  }
  document.getElementById("f").addEventListener("submit", async function(ev){
    ev.preventDefault();
    err.textContent = ""; go.disabled = true; go.textContent = "Checking\\u2026";
    try {
      var key = await derive(document.getElementById("pw").value);
      var raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
      try { await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(P.i)}, key, unb64(P.d)); }
      catch (e) { throw new Error("bad"); }
      if (document.getElementById("rm").checked && s) {
        try { s.setItem(KEY, btoa(String.fromCharCode.apply(null, raw))); } catch (e) {}
      }
      await open(key);
    } catch (e) {
      err.textContent = "That password didn't work. Please try again.";
      go.disabled = false; go.textContent = "View report";
      document.getElementById("pw").select();
    }
  });
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())
