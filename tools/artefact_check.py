#!/usr/bin/env python3
"""artefact-check — compares the published artefacts against each other.

Three checks, all read-only:

  keys-symmetry   every kid in did.json appears in jwks.json and the reverse
  keys-have-code  every kid in jwks.json has a code path that signs with it
  urls-resolve    every URL named in a published artefact answers, and a 404 on
                  a publicly named URL is a deviation

A deviation listed in the register is reported and does not fail the run. A
deviation that is not listed fails it. A registered deviation that has
disappeared is also reported, and its entry is closed.

Standard library only, so it runs from cron without a virtualenv.

  artefact_check.py            run the checks, write the report, exit 1 on a new
                               or vanished deviation
  artefact_check.py --only keys  only the key checks, which need no local files
  artefact_check.py --baseline print register entries for everything found now

A run compares only the checks it performed. Asking whether an entry has vanished
is only meaningful for a check that ran, so --only keys leaves every urls-resolve
entry alone rather than reading its absence as a fix.
"""
import datetime
import html
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

HOME = pathlib.Path(os.path.expanduser("~"))
ROOT = pathlib.Path(__file__).resolve().parents[1]
# The register lives next to the vectors, in this repository. A closed entry
# therefore leaves a tracked change for someone to commit, which is the audit
# trail rather than a side effect.
REGISTER = ROOT / "deviations.json"
REPORT_DIR = pathlib.Path(os.environ.get("ARTEFACT_REPORT_DIR", HOME / "Downloads"))
# Two inputs are about the machine this runs on, not about the repository:
# the served web root and a checkout of moltrust-api to grep for a kid.
REPO = pathlib.Path(os.environ.get("MOLTRUST_API_CHECKOUT", "/home/moltstack/moltstack"))
WEBROOT = pathlib.Path(os.environ.get("MOLTRUST_WEBROOT", "/var/www/html"))
NOW = datetime.datetime.now(datetime.UTC)

DID_JSON = "https://api.moltrust.ch/.well-known/did.json"
JWKS_JSON = "https://api.moltrust.ch/.well-known/jwks.json"

# Artefacts whose text is published and therefore whose URLs are a promise.
PUBLISHED_FILES = [
    WEBROOT / "did-method-spec.html",
]
PUBLISHED_JSON_URLS = [
    DID_JSON,
    JWKS_JSON,
    "https://api.moltrust.ch/.well-known/agent.json",
    "https://api.moltrust.ch/.well-known/agent-card.json",
]
# Where a kid would be used to sign.
CODE_DIRS = ["app", "services", "scripts", "agents", "workers"]

URL_RE = re.compile(r"https?://[^\s\"'<>)\]}\\]+")
# Trailing punctuation that belongs to the prose, not the URL.
TRIM = ".,;:!?)»"


class RunAborted(Exception):
    """The run could not be carried out. Not a verdict about conformance."""


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={
        "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        "User-Agent": "moltrust-artefact-check/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception as e:                       # DNS, TLS, timeout
        return None, str(e).encode()


def head_status(url, timeout=20):
    """Status for a URL. HEAD first, GET when a host refuses HEAD."""
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method, headers={
            "User-Agent": "moltrust-artefact-check/1.0",
            "Accept": "*/*",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, ""
        except urllib.error.HTTPError as e:
            if method == "HEAD" and e.code in (403, 405, 501):
                continue                         # try GET
            return e.code, ""
        except Exception as e:
            if method == "HEAD":
                continue
            return None, f"{type(e).__name__}: {e}"
    return None, "both HEAD and GET failed"


# --------------------------------------------------------------- the checks

def check_keys_symmetry(deviations):
    status, body = fetch(DID_JSON)
    if status != 200:
        raise RunAborted(f"{DID_JSON} answered {status}; the key checks cannot "
                         "be carried out, so nothing is reported about them")
    did = json.loads(body)
    status, body = fetch(JWKS_JSON)
    if status != 200:
        raise RunAborted(f"{JWKS_JSON} answered {status}; the key checks cannot "
                         "be carried out, so nothing is reported about them")
    jwks = json.loads(body)

    did_kids = {v.get("id") for v in did.get("verificationMethod", []) if v.get("id")}
    jwks_kids = {k.get("kid") for k in jwks.get("keys", []) if k.get("kid")}

    for kid in sorted(did_kids - jwks_kids):
        roles = [r for r in ("assertionMethod", "authentication", "keyAgreement")
                 if kid in (did.get(r) or [])]
        deviations.append(dev(
            "keys-symmetry", f"kid in did.json without a JWK: {kid}",
            "A verifier is pointed at this verification method"
            + (f" for {', '.join(roles)}" if roles else "")
            + ", and jwks.json publishes no key under that kid."))
    for kid in sorted(jwks_kids - did_kids):
        deviations.append(dev(
            "keys-symmetry", f"kid in jwks.json without a verification method: {kid}",
            "jwks.json publishes this as a signing key (use=sig) and the DID "
            "document does not declare it, so a verifier following the DID "
            "document will not accept a signature made with it."))
    return did_kids, jwks_kids


def check_keys_have_code(jwks_kids, deviations):
    if not jwks_kids:
        return
    try:
        grep_repo("")
    except FileNotFoundError as e:
        print(f"  keys-have-code nicht durchgefuehrt: {e}")
        return False
    for kid in sorted(jwks_kids):
        hits = grep_repo(kid)
        if not hits:
            deviations.append(dev(
                "keys-have-code", f"no code path signs with kid {kid}",
                "The kid literal appears in none of "
                f"{', '.join(CODE_DIRS)} under {REPO}. Either a signer builds "
                "the kid at runtime, in which case this check needs that "
                "expression, or the key is published and unused."))


def grep_repo(needle):
    dirs = [str(REPO / d) for d in CODE_DIRS if (REPO / d).is_dir()]
    if not dirs:
        # No checkout here. Returning [] would turn "cannot look" into "no code
        # path signs with this kid", which is a deviation this run did not earn.
        raise FileNotFoundError(
            f"kein moltrust-api-Checkout unter {REPO}; setze MOLTRUST_API_CHECKOUT")
    r = subprocess.run(
        ["grep", "-rIl", "--exclude-dir=__pycache__", "--exclude=*.bak*",
         "--exclude=*.pyc", "-F", needle, *dirs],
        capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if l.strip()]


def collect_urls():
    """Every URL our published artefacts name, with where it was named."""
    found = {}

    def add(url, where):
        url = url.rstrip(TRIM)
        # A template is not an address. did-method-spec.html and the agent card
        # name paths like /identity/resolve/{did}, which no status code describes.
        if any(c in url for c in "{}<>") or "%7B" in url.upper():
            return
        if len(url) < 12 or url.endswith(("/.", "//")):
            return
        # A bare scheme+host is a connection hint, not a named document. The
        # spec page preconnects to fonts.googleapis.com and the agent card names
        # https://api.moltrust.ch as a base; neither promises a page there.
        rest = url.split("://", 1)[1]
        if "/" not in rest.rstrip("/") or not rest.split("/", 1)[1].strip("/"):
            return
        found.setdefault(url, set()).add(where)

    for p in PUBLISHED_FILES:
        if not p.is_file():
            # Narrowing the URL set because a file is missing would turn "did
            # not look there" into "nothing is wrong there".
            raise RunAborted(
                f"{p} fehlt; die URL-Pruefung kann nicht durchgefuehrt werden. "
                "Setze MOLTRUST_WEBROOT, oder rufe mit --only keys auf")
        text = html.unescape(p.read_text(encoding="utf-8", errors="replace"))
        for m in URL_RE.finditer(text):
            add(m.group(0), p.name)

    for u in PUBLISHED_JSON_URLS:
        status, body = fetch(u)
        if status != 200:
            continue
        for m in URL_RE.finditer(html.unescape(body.decode("utf-8", "replace"))):
            add(m.group(0), u.rsplit("/", 1)[-1])

    return found


def check_urls(deviations):
    urls = collect_urls()
    results = []
    for url in sorted(urls):
        status, note = head_status(url)
        results.append((url, status, sorted(urls[url]), note))
        if status is None:
            deviations.append(dev(
                "urls-resolve", f"URL named publicly does not answer: {url}",
                f"named in {', '.join(sorted(urls[url]))}; {note}"))
        elif status in (404, 410):
            # Only "not there" counts. 405 means the path exists under another
            # method, 401 and 403 mean it exists and is guarded; neither is a
            # broken promise about the address.
            deviations.append(dev(
                "urls-resolve", f"URL named publicly answers {status}: {url}",
                f"named in {', '.join(sorted(urls[url]))}"))
    return results


# ------------------------------------------------------------------ register

def dev(check, what, detail):
    return {"check": check, "what": what, "detail": detail,
            "first_seen": NOW.isoformat(timespec="seconds")}


def key_of(d):
    return f"{d['check']}::{d['what']}"


def load_register():
    if REGISTER.is_file():
        return json.loads(REGISTER.read_text())
    return {"created": NOW.isoformat(timespec="seconds"), "entries": {}}


def main():
    only = None
    if "--only" in sys.argv:
        i = sys.argv.index("--only")
        if i + 1 >= len(sys.argv) or sys.argv[i + 1] not in ("keys", "urls", "all"):
            print("--only braucht keys, urls oder all", file=sys.stderr)
            return 2
        only = sys.argv[i + 1]
        only = None if only == "all" else only

    deviations = []
    url_results = []
    # The checks this run performs. An entry whose check is not in here is left
    # alone: this run has nothing to say about it.
    ran = set()
    try:
        if only in (None, "keys"):
            did_kids, jwks_kids = check_keys_symmetry(deviations)
            ran.add("keys-symmetry")
            if check_keys_have_code(jwks_kids, deviations) is not False:
                ran.add("keys-have-code")
        else:
            did_kids = jwks_kids = None
        if only in (None, "urls"):
            url_results = check_urls(deviations)
            ran.add("urls-resolve")
    except RunAborted as e:
        # Exit 2, and the register is not touched: an entry may only be closed by
        # a run that looked and did not find it.
        print(f"Lauf nicht durchfuehrbar: {e}", file=sys.stderr)
        return 2

    found = {key_of(d): d for d in deviations}

    if "--baseline" in sys.argv:
        reg = {"created": NOW.isoformat(timespec="seconds"), "entries": {}}
        for k, d in found.items():
            reg["entries"][k] = {**d, "status": "open",
                                 "why": "recorded at register creation, cause not yet established"}
        REGISTER.parent.mkdir(parents=True, exist_ok=True)
        REGISTER.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")
        REGISTER.chmod(0o644)
        print(f"Register angelegt: {REGISTER}  ({len(found)} Eintraege)")
        return 0

    reg = load_register()
    # Entries this check watches. The register is shared with did-conformance,
    # and an entry it owns says nothing about whether this check should still
    # find something: scoping by source is what keeps one tool from closing the
    # other's entries.
    MINE = "artefact-check"
    known = {k: v for k, v in reg["entries"].items() if v.get("status") == "open"}
    # Mine, and from a check this run actually carried out. Either condition
    # alone has already produced a wrong closure: scoping only by tool closed six
    # URL entries in CI, where there is no web root to read them from.
    mine_open = {k: v for k, v in known.items()
                 if v.get("source", MINE) == MINE and v.get("check") in ran}

    new = [d for k, d in found.items() if k not in known]
    vanished = [k for k in mine_open if k not in found]

    for k in vanished:
        reg["entries"][k]["status"] = "closed"
        reg["entries"][k]["closed_at"] = NOW.isoformat(timespec="seconds")
    if vanished:
        REGISTER.write_text(json.dumps(reg, indent=2, ensure_ascii=False,
                                       sort_keys=True) + "\n")
        print(f"  {REGISTER} geaendert: {len(vanished)} Eintrag/Eintraege "
              f"geschlossen — die Datei ist versioniert und will committet werden")

    stamp = NOW.strftime("%Y-%m-%d")
    report = REPORT_DIR / f"artefact-check-{stamp}.md"
    lines = [f"# artefact-check {NOW.isoformat(timespec='seconds')}", ""]
    lines.append(f"- did.json kids: {len(did_kids or [])}")
    lines.append(f"- jwks.json kids: {len(jwks_kids or [])}")
    lines.append(f"- URLs geprueft: {len(url_results)}")
    lines.append(f"- durchgefuehrte Pruefungen: {', '.join(sorted(ran)) or 'keine'}")
    lines.append(f"- Abweichungen gefunden: {len(found)}")
    lines.append(f"- davon im Register: {len(found) - len(new)}")
    lines.append(f"- neu: {len(new)}   verschwunden: {len(vanished)}")
    lines.append("")
    if new:
        lines.append("## Neue Abweichungen")
        for d in new:
            lines.append(f"- **{d['check']}** — {d['what']}")
            lines.append(f"  {d['detail']}")
        lines.append("")
    if vanished:
        lines.append("## Verschwunden, Eintrag geschlossen")
        for k in vanished:
            lines.append(f"- {k}")
        lines.append("")
    lines.append("## Alle Abweichungen dieses Laufs")
    for d in sorted(found.values(), key=key_of):
        mark = "NEU" if key_of(d) in {key_of(x) for x in new} else "bekannt"
        lines.append(f"- [{mark}] **{d['check']}** — {d['what']}")
        lines.append(f"  {d['detail']}")
    lines.append("")
    lines.append("## URL-Ergebnisse")
    lines.append("")
    lines.append("| Status | URL | genannt in |")
    lines.append("|---|---|---|")
    for url, status, where, note in url_results:
        lines.append(f"| {status if status is not None else 'kein Abschluss'} "
                     f"| {url} | {', '.join(where)} |")
    report.write_text("\n".join(lines) + "\n")
    report.chmod(0o644)

    print(f"Bericht: {report}")
    print(f"Abweichungen: {len(found)} gesamt, {len(new)} neu, {len(vanished)} verschwunden")
    for d in new:
        print(f"  NEU  {d['check']}: {d['what']}")
    for k in vanished:
        print(f"  WEG  {k}")
    return 1 if (new or vanished) else 0


if __name__ == "__main__":
    sys.exit(main())
