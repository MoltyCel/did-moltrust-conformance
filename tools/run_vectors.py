#!/usr/bin/env python3
"""Run every vector and say what held, what did not, and what is registered.

Exit status:
  0  everything either held or is a registered deviation
  1  a vector failed that is not in the register, or a registered deviation has
     disappeared and its entry needs closing
  2  the run could not be carried out (a target unreachable, a vector unreadable)

A target that cannot be reached is a run condition, not a deviation: the run
stops with 2 rather than reporting the whole target as non-conformant.

  run_vectors.py                  all vectors
  run_vectors.py --check syntax   only one kind
  run_vectors.py --json out.json  machine-readable result as well
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors"
REGISTER = ROOT / "deviations.json"

API = os.environ.get("MOLTRUST_API", "https://api.moltrust.ch").rstrip("/")
DRIVER = os.environ.get("MOLTRUST_DRIVER", "https://uresolver.moltrust.ch").rstrip("/")

# Section 2.2.
SYNTAX = re.compile(r"^did:moltrust:[0-9a-f]{16}$")

# How each target names the same outcome.
CODES = {
    "api": {"RESOLVES": (200, None), "NOT_FOUND": (404, "did_not_found"),
            "INVALID_DID": (400, "invalid_did"),
            "UNSUPPORTED_METHOD": (400, "unsupported_method")},
    "driver": {"RESOLVES": (200, None), "NOT_FOUND": (404, "notFound"),
               "INVALID_DID": (400, "invalidDid"),
               "UNSUPPORTED_METHOD": (400, "methodNotSupported")},
}


class Unreachable(Exception):
    pass


def request(url, method="GET", body=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json", "User-Agent": "did-moltrust-conformance/1.0"}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw.strip() else None)
        except json.JSONDecodeError:
            return e.code, None
    except Exception as e:
        raise Unreachable(f"{url}: {type(e).__name__}: {e}")


def api_reason(body):
    """The API carries its code under detail, which is an object since 2026-10-06."""
    if not isinstance(body, dict):
        return None
    d = body.get("detail")
    if isinstance(d, dict):
        return d.get("error")
    if isinstance(d, str):
        return d
    return body.get("error")


def driver_reason(body):
    if isinstance(body, dict):
        return (body.get("didResolutionMetadata") or {}).get("error")
    return None


def observe(target, vec):
    """Ask one target and return (http_status, reason_code)."""
    inp = vec["input"]
    if vec["check"] == "bridge":
        status, body = request(f"{API}/identity/bridge-simple", "POST",
                               inp.get("body", {}))
        return status, api_reason(body)
    # plain by default: HttpDriver.java inserts the $1 placeholder verbatim, so a
    # Universal Resolver sends the colons unencoded, and that is the path a peer
    # actually hits. encoded is the other legal form and has its own vector.
    if vec.get("path_form", "plain") == "encoded":
        did = urllib.parse.quote(inp["did"], safe="")
    else:
        did = inp["did"]
    if target == "api":
        status, body = request(f"{API}/identity/resolve/{did}")
        return status, api_reason(body)
    status, body = request(f"{DRIVER}/1.0/identifiers/{did}")
    return status, driver_reason(body)


def check_syntax(vec):
    did = vec["input"]["did"]
    conforms = bool(SYNTAX.match(did))
    want = vec["expected"]["result"] == "CONFORMS"
    return conforms == want, f"matched={conforms}, erwartet={want}"


def check_derivation(vec):
    inp = vec["input"]
    expected = vec["expected"]["result"]
    if "public_key_hex" in inp:
        want = inp["did"].split(":")[-1]
        got = hashlib.sha256(bytes.fromhex(inp["public_key_hex"])).hexdigest()[:16]
        derived = got == want
        return derived == (expected == "CONFORMS"), (
            f"abgeleitet {got}, im Identifier {want}, erwartet {expected}")
    if expected == "LEGACY":
        # Section 2.2 carve-out: a 1.0 identifier resolves, and nothing in the
        # result says it was issued under 1.1. identifierRule is the proposed
        # name; until it is fixed, its absence is not a failure.
        did = urllib.parse.quote(inp["did"], safe="")
        status, body = request(f"{API}/identity/resolve/{did}")
        if status != 200 or not isinstance(body, dict):
            return False, f"1.0-Identifier nicht aufloesbar: HTTP {status}"
        meta = body.get("didDocumentMetadata") or {}
        rule = meta.get("identifierRule") if isinstance(meta, dict) else None
        if rule not in (None, "1.0"):
            return False, f"aufloesbar, aber identifierRule={rule!r}"
        return True, f"aufloesbar, identifierRule={rule!r}"
    # Live: take the key the registry publishes and derive from it.
    did = urllib.parse.quote(inp["did"], safe="")
    status, body = request(f"{API}/identity/resolve/{did}")
    if status != 200 or not isinstance(body, dict):
        return False, f"DID nicht aufloesbar: HTTP {status}"
    vms = body.get("verificationMethod") or []
    keys = [v.get("publicKeyHex") for v in vms if v.get("publicKeyHex")]
    if not keys:
        return False, "Dokument fuehrt keinen publicKeyHex"
    want = inp["did"].split(":")[-1]
    got = hashlib.sha256(bytes.fromhex(keys[0])).hexdigest()[:16]
    return got == want, f"aus dem Schluessel {got}, im Identifier {want}"


def check_resolve(vec):
    """One vector asks one target, so one answer decides."""
    t = vec.get("target", "api")
    status, reason = observe(t, vec)
    w_status = vec["expected"].get("http_status")
    w_reason = vec["expected"].get("reason_code")
    if w_status is None:
        w_status, w_reason = CODES[t][vec["expected"]["result"]]
    good = status == w_status and (w_reason is None or reason == w_reason)
    return good, f"{t}: {status}/{reason} erwartet {w_status}/{w_reason}"


def check_bridge(vec):
    status, reason = observe("api", vec)
    w = vec["expected"].get("http_status")
    return status == w, f"api: {status}/{reason} erwartet {w}"


def check_deployment(vec):
    """Does the running driver behave like the version it reports?

    Two codebases both called themselves 1.0.0 and answered a malformed
    identifier differently - notFound from the service deployed at
    uresolver.moltrust.ch, internalError from the published image. A version
    string cannot settle that; a commit can, which is why /health has to carry
    one. So this asks two things at once:

      /health names a commit, not only a version
      the malformed identifier answers invalidDid

    A service that cannot name its commit fails the first half, and a service
    running other code than it claims fails the second.
    """
    status, body = request(f"{DRIVER}/health")
    if status != 200 or not isinstance(body, dict):
        return False, f"/health: HTTP {status}"
    commit = body.get("commit")
    reported = f"commit={commit!r} version={body.get('version')!r}"
    if not commit or commit == "unknown" or not re.fullmatch(r"[0-9a-f]{7,40}", commit):
        return False, (f"/health nennt keinen pruefbaren Commit: {reported}; "
                       "eine gepflegte Versionszeichenkette kann nicht belegen, "
                       "welcher Code laeuft")
    probe = {"input": {"did": "did:moltrust:ambassador0001"}, "check": "resolve",
             "target": "driver"}
    pstatus, preason = observe("driver", probe)
    if pstatus == 400 and preason == "invalidDid":
        return True, f"{reported}, und ambassador0001 -> 400/invalidDid"
    return False, (f"{reported}, aber ambassador0001 -> {pstatus}/{preason}; "
                   "das Verhalten passt nicht zu der angegebenen Fassung")


def check_lookup(vec):
    path = vec["input"]["path"].replace(
        "{did}", urllib.parse.quote(vec["input"]["did"], safe=":"))
    status, body = request(f"{API}{path}")
    w = vec["expected"].get("http_status")
    return status == w, f"api {path}: {status}/{api_reason(body)} erwartet {w}"


RUNNERS = {"syntax": check_syntax, "derivation": check_derivation,
           "lookup": check_lookup,
           "resolve": check_resolve, "bridge": check_bridge,
           "deployment": check_deployment}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", choices=sorted(RUNNERS))
    ap.add_argument("--json")
    args = ap.parse_args()

    reg = json.loads(REGISTER.read_text()) if REGISTER.is_file() else {"entries": {}}
    entries = reg.get("entries", {})

    files = sorted(VECTORS.glob("*.json"))
    if not files:
        print("keine Vektoren in vectors/", file=sys.stderr)
        return 2

    results, unreachable = [], []
    for f in files:
        vec = json.loads(f.read_text())
        if args.check and vec["check"] != args.check:
            continue
        try:
            held, note = RUNNERS[vec["check"]](vec)
        except Unreachable as e:
            unreachable.append(f"{vec['id']}: {e}")
            continue
        known = vec.get("known_deviation")
        open_known = known in entries and entries[known].get("status") == "open"
        results.append({"id": vec["id"], "name": vec["name"],
                        "section": vec["section_ref"], "check": vec["check"],
                        "held": held, "note": note,
                        "known_deviation": known, "registered_open": open_known})

    if unreachable:
        print("Lauf nicht durchfuehrbar, Ziel nicht erreichbar:", file=sys.stderr)
        for u in unreachable:
            print(f"  {u}", file=sys.stderr)
        return 2

    new = [r for r in results if not r["held"] and not r["registered_open"]]
    expected_fail = [r for r in results if not r["held"] and r["registered_open"]]
    # Only an observable entry can vanish by a vector holding. A documentation
    # defect carries observable: false and is closed by a person, not by a run.
    vanished = [r for r in results if r["held"] and r["registered_open"]
                and entries.get(r["known_deviation"], {}).get("observable", True)]
    passed = [r for r in results if r["held"] and not r["registered_open"]]

    print(f"Vektoren: {len(results)}   gehalten {len(passed)}   "
          f"registriert abweichend {len(expected_fail)}   "
          f"neu abweichend {len(new)}   registriert aber behoben {len(vanished)}")
    print(f"API {API}   Treiber {DRIVER}")
    for r in new:
        print(f"  NEU   {r['id']} (section {r['section']}) {r['name']}")
        print(f"        {r['note']}")
    for r in vanished:
        print(f"  WEG   {r['id']} {r['known_deviation']} haelt jetzt — Eintrag schliessen")
    for r in expected_fail:
        print(f"  bekannt {r['id']} {r['known_deviation']}")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps({
            "api": API, "driver": DRIVER, "results": results,
            "summary": {"total": len(results), "held": len(passed),
                        "registered": len(expected_fail), "new": len(new),
                        "vanished": len(vanished)}}, indent=2) + "\n")
        print(f"  JSON: {args.json}")

    return 1 if (new or vanished) else 0


if __name__ == "__main__":
    sys.exit(main())
