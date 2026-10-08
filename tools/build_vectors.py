#!/usr/bin/env python3
"""Write vectors/*.json from the table below, so the set is one reviewable file.

Every vector names the section it comes from. The expected outcome is what the
specification requires, never what the implementation currently does — a vector
that fails today carries known_deviation and the register says why.

  build_vectors.py            write the vectors
  build_vectors.py --check    fail if the files on disk differ from the table
"""
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors"

# A key used only here, so the derivation vector carries a real Ed25519 public
# key rather than a made-up hex string. Generated once, never a signing key.
SAMPLE_PUBKEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

# The public key of RFC 8032 section 7.1, test 1. Section 2.2 (v0.2) works its
# example from it, so the specification and this table quote the same bytes.
RFC8032_TEST1_PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def derive(pubkey_hex: str) -> str:
    """Section 2.2: the first 8 bytes of SHA-256 over the public key."""
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:16]


SYNTAX_OK = [
    ("0123456789abcdef", "sixteen lowercase hex characters"),
    ("d34ed796a4dc4698", "the example from section 2.2"),
    ("ffffffffffffffff", "all f, still sixteen hex"),
    ("0000000000000000", "all zero, still sixteen hex"),
]

SYNTAX_BAD = [
    ("ambassador0001", "letters outside a-f"),
    ("vcone", "five letters, not hex, too short"),
    ("ABCDEF0123456789", "uppercase; section 2.2 says lowercase"),
    ("0123456789abcde", "fifteen characters"),
    ("0123456789abcdef0", "seventeen characters"),
    ("", "empty method-specific identifier"),
    ("0123456789abcdeg", "g is not a hex digit"),
    ("ext_0123456789abcdef", "the ext_ prefix, which section 2.2 does not define"),
    ("0123456789abcdef ", "a trailing space"),
    ("0123-456789abcdef", "a hyphen inside the identifier"),
]

# The method comes first in the name, because that is what distinguishes these
# three from each other and an id is derived from the name.
FOREIGN = [
    ("did:example", "did:example:0123456789abcdef",
     "the method reserved for examples"),
    ("did:key", "did:key:z6MkhaXgBZDvotDkL5257faiz",
     "a method with no registry behind it"),
    ("did:aps", "did:aps:ef8bbf57911681e4a2965ee6",
     "a peer ecosystem we bridge to but do not resolve"),
]

vectors = []
_ids = {}


def slug(text, limit=40):
    """A stable, readable handle. Only what a reader would type.

    The target is stripped here and appended by add(), so truncation can never
    eat the part that distinguishes two vectors. The first version cut the whole
    name at 52 characters and lost exactly that.
    """
    s = text.lower()
    for noise in ("did:moltrust:", "[api]", "[driver]", "[", "]"):
        s = s.replace(noise, "")
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return re.sub(r"-{2,}", "-", s).strip("-")[:limit].rstrip("-")


def add(**kw):
    """Derive the id from the check, the name and the target, never from the
    position.

    Three vectors were inserted on 2026-10-06 and the deployment vector moved
    from did-vector-032 to did-vector-035, which invalidated a register entry
    and a report naming the old number. An id must change only when the vector
    does.
    """
    parts = [f"did-{kw['check']}", slug(kw["name"])]
    target = kw.get("target", "none")
    if target not in (None, "none"):
        parts.append(target)
    if kw.get("path_form") == "encoded":
        parts.append("encoded")
    vid = "-".join(parts)
    if vid in _ids:
        raise SystemExit(
            f"zwei Vektoren ergeben dieselbe id {vid!r}:\n"
            f"  {_ids[vid]!r}\n  {kw['name']!r}\n"
            "Namen unterscheiden, nicht die id von Hand setzen.")
    _ids[vid] = kw["name"]
    kw["id"] = vid
    vectors.append(kw)
    return kw


# --- section 2.2, syntax only, no service involved ------------------------
for tail, why in SYNTAX_OK:
    add(name=f"well-formed identifier: {why}",
        description=f"did:moltrust:{tail} matches [0-9a-f]{{16}}.",
        section_ref="2.2", check="syntax", target="none",
        input={"did": f"did:moltrust:{tail}"},
        expected={"result": "CONFORMS"},
        rationale="Section 2.2 defines method-specific-id := [0-9a-f]{16}. "
                  f"This identifier is {why} and therefore conforms.")

for tail, why in SYNTAX_BAD:
    add(name=f"malformed identifier: {why}",
        description=f"did:moltrust:{tail!r} does not match [0-9a-f]{{16}}.",
        section_ref="2.2", check="syntax", target="none",
        input={"did": f"did:moltrust:{tail}"},
        expected={"result": "INVALID_DID"},
        rationale="Section 2.2 defines method-specific-id := [0-9a-f]{16}. "
                  f"This identifier fails because of {why}, so it is not a "
                  "did:moltrust identifier at all.")

# --- section 2.2, the derivation clause -----------------------------------
add(name="the identifier follows from the public key",
    description="Section 2.2 does not only give a shape, it says where the "
                "identifier comes from: the first 8 bytes of the SHA-256 hash "
                "of the agent's Ed25519 public key at registration time.",
    section_ref="2.2", check="derivation", target="none",
    input={"public_key_hex": SAMPLE_PUBKEY,
           "did": f"did:moltrust:{derive(SAMPLE_PUBKEY)}"},
    expected={"result": "CONFORMS"},
    rationale="SHA-256 over the 32 raw key bytes, first 8 bytes as lowercase "
              "hex. This vector checks the arithmetic itself and is the "
              "reference a registered DID is compared against.",
    )

add(name="the RFC 8032 test key gives the identifier of the specification example",
    description="Section 2.2 (v0.2) works its example of rule "
                "derived-sha256-ed25519-8 from the "
                "public key of RFC 8032 section 7.1 test 1. The identifier has "
                "to be the one the text prints.",
    section_ref="2.2", check="derivation", target="none",
    input={"public_key_hex": RFC8032_TEST1_PUBKEY,
           "did": "did:moltrust:21fe31dfa154a261"},
    expected={"result": "CONFORMS"},
    rationale="The value 21fe31dfa154a261 is written into the specification, "
              "computed with openssl over the 32 raw bytes. This vector holds "
              "the text and the arithmetic to each other.",
    )

add(name="hashing the hex text of the key is not the derivation",
    description="The derivation hashes the 32 raw key bytes. An implementation "
                "that hashes the 64-character hex string produces a "
                "well-formed identifier that does not derive from the key.",
    section_ref="2.2", check="derivation", target="none",
    input={"public_key_hex": RFC8032_TEST1_PUBKEY,
           "did": "did:moltrust:"
                  + hashlib.sha256(RFC8032_TEST1_PUBKEY.encode()).hexdigest()[:16]},
    expected={"result": "NOT_DERIVED"},
    rationale="The likeliest way to get the clause wrong while every syntax "
              "check stays green. A vector that only ever passes measures "
              "nothing.",
    )

add(name="an assigned identifier stays resolvable and claims no derivation",
    description="Section 2.2 keeps every identifier issued before v0.2 "
                "(rule assigned-opaque) resolvable and gives no assurance that "
                "it derives from a key. The example identifier of section 2.2 "
                "is one of them.",
    section_ref="2.2", check="derivation", target="api",
    input={"did": "did:moltrust:d34ed796a4dc4698"},
    expected={"result": "ASSIGNED"},
    rationale="The carve-out has two halves a run can watch: the identifier "
              "still resolves, and the resolution result does not report it as "
              "derived. Whether it happens to recompute from its key "
              "is not asked, because the text promises nothing either way.",
    )

# --- section 4.2, resolution outcomes ------------------------------------
# One vector, one target, one claim. A vector that asked two services at once
# could hold on one and fail on the other, and then a single register entry
# excused both halves.
# Closed 2026-10-06 once the service ran the published image and the four vectors
# below held. The mark is gone with it: a return of the defect must show up as a
# new deviation and fail the run, not as a known one that is quietly reported.
DEPLOY_DEV = None

RESOLVE_CASES = [
    ("a registered identifier resolves to a DID document",
     "did:moltrust:d34ed796a4dc4698", "4.2", "RESOLVES",
     {"api": (200, None), "driver": (200, None)},
     "Section 4.2 describes resolution as a GET that returns the DID document. "
     "Section 3.1 uses this identifier as its example.", {}),
    ("a well-formed identifier nobody registered is not found",
     "did:moltrust:0000000000000000", "4.2", "NOT_FOUND",
     {"api": (404, "did_not_found"), "driver": (404, "notFound")},
     "A conformant identifier that was never registered is absent, not "
     "malformed. Saying invalid here would send an implementer to check their "
     "string instead of their registration.", {}),
    ("a malformed identifier is invalidDid, not an internal error",
     "did:moltrust:ambassador0001", "2.2", "INVALID_DID",
     {"api": (400, "invalid_did"), "driver": (400, "invalidDid")},
     "The method is ours and the identifier is not well formed, so the answer "
     "must name the identifier. Reported from outside on "
     "decentralized-identity/universal-resolver#541, where the driver reported "
     "internalError with 'Registry returned 400'.",
     {"driver": DEPLOY_DEV}),
    ("the other pre-convention identifier behaves the same",
     "did:moltrust:vcone", "2.2", "INVALID_DID",
     {"api": (400, "invalid_did"), "driver": (400, "invalidDid")},
     "Two rows predate the 16-hex convention. Both must answer the same way, so "
     "neither becomes a special case.",
     {"driver": DEPLOY_DEV}),
    ("the ext_ prefix is not a did:moltrust identifier",
     "did:moltrust:ext_516a656bafa39e5c", "2.2", "INVALID_DID",
     {"api": (400, "invalid_did"), "driver": (400, "invalidDid")},
     "Section 2.2 defines no prefix, and section 6 describes the bridge without "
     "one. Eighteen of the nineteen bridge rows map to a conformant identifier.",
     {"api": "ext_::DID_PATTERN accepts a prefix the specification does not define",
      "driver": DEPLOY_DEV}),
]

for title, did, sec, result, per_target, why, devs in RESOLVE_CASES:
    for tgt in ("api", "driver"):
        status, reason = per_target[tgt]
        kw = {"name": f"{title} [{tgt}]",
              "description": f"{did} against the {tgt}.",
              "section_ref": sec, "check": "resolve", "target": tgt,
              "input": {"did": did},
              "expected": {"result": result, "http_status": status,
                           "reason_code": reason},
              "rationale": why}
        if devs.get(tgt):
            kw["known_deviation"] = devs[tgt]
        add(**kw)

for method, did, why in FOREIGN:
    add(name=f"{method} is refused as a foreign method",
        description=f"{did} is not a did:moltrust identifier — {why}.",
        section_ref="4.2", check="resolve", target="api",
        input={"did": did},
        expected={"result": "UNSUPPORTED_METHOD", "http_status": 400,
                  "reason_code": "unsupported_method"},
        rationale="An unknown method and a malformed identifier of a known "
                  "method are different problems and must not share an answer.")

add(name="the organisation did:web identifier still resolves",
    description="did:web:api.moltrust.ch, the root the registry controls.",
    section_ref="4.2", check="resolve", target="api",
    input={"did": "did:web:api.moltrust.ch"},
    expected={"result": "RESOLVES", "http_status": 200, "reason_code": None},
    rationale="The registry serves did:web for its own root. This vector is "
              "here so a change to the did:moltrust branches cannot quietly "
              "take did:web with it.")

# --- section 2.2 on the read endpoints ----------------------------------
# /reputation/query is the lookup asked because it reads without touching the
# agent row: /identity/badge and /agents/{did}/erc8004 write agents.last_seen,
# so a conformance run against them would make the agents it names look active.
add(name="a lookup endpoint refuses an identifier outside section 2.2",
    description="The read endpoints that take a DID in the path apply the "
                "section 2.2 syntax, the same as the resolver. A lookup that "
                "answers for an identifier the resolver calls malformed "
                "contradicts it.",
    section_ref="2.2", check="lookup", target="api",
    input={"did": "did:moltrust:vcone", "path": "/reputation/query/{did}"},
    expected={"result": "INVALID_DID", "http_status": 400},
    rationale="/identity/resolve refuses did:moltrust:vcone as invalid_did. "
              "Fifteen read sites accepted anything in [a-z0-9_-]{1,64} and "
              "answered for it.",
    known_deviation="lookup::read endpoints accept identifiers outside section 2.2")

# --- section 6, the bridge -----------------------------------------------
add(name="the bridge endpoint exists and is guarded",
    description="POST /identity/bridge-simple with no body and no key.",
    section_ref="6", check="bridge", target="api",
    input={"body": {}},
    expected={"result": "INVALID_DID", "http_status": 401, "reason_code": None},
    rationale="Section 6 names POST /identity/bridge-simple and shows the call "
              "with Content-Type only. The endpoint requires X-API-Key, so an "
              "unauthenticated call answers 401. That the answer is 401 and not "
              "404 is what tells an implementer the path is right; that the "
              "section omits the header is recorded as a deviation of its own, "
              "without a vector: a sentence missing from a document is not "
              "something a runner can watch fail.")

# --- both address forms, and a method we do not serve ---------------------
add(name="a percent-encoded DID is the same address [driver]",
    description="did%3Amoltrust%3Ad34ed796a4dc4698 must answer exactly as the "
                "plain form does.",
    section_ref="4.2", check="resolve", target="driver", path_form="encoded",
    input={"did": "did:moltrust:d34ed796a4dc4698"},
    expected={"result": "RESOLVES", "http_status": 200, "reason_code": None},
    rationale="RFC 3986 allows a colon unencoded in a path segment, and "
              "percent-encoding it yields an equivalent URI. On 2026-10-06 the "
              "driver answered the plain form and gave the encoded one a "
              "plain-text 404 with no resolution metadata at all, because a Hono "
              "route pattern matched the raw path. HttpDriver.java sends the "
              "plain form for a $1 placeholder and the encoded form for $2 or "
              "when resolution options are present, so both reach a driver in "
              "practice.")

add(name="a malformed identifier is invalidDid in the encoded form too [driver]",
    description="The reported identifier, percent-encoded.",
    section_ref="2.2", check="resolve", target="driver", path_form="encoded",
    input={"did": "did:moltrust:ambassador0001"},
    expected={"result": "INVALID_DID", "http_status": 400,
              "reason_code": "invalidDid"},
    rationale="The regression of 2026-10-06 turned this into a 404 without a "
              "reason code, which a resolver cannot report and a caller cannot "
              "tell from an absent service.")

add(name="a method we do not serve is methodNotSupported [driver]",
    description="did:example:0123456789abcdef against the driver.",
    section_ref="4.2", check="resolve", target="driver",
    input={"did": "did:example:0123456789abcdef"},
    expected={"result": "UNSUPPORTED_METHOD", "http_status": 400,
              "reason_code": "methodNotSupported"},
    rationale="The branch returning this code existed and was unreachable: the "
              "route pattern :did{did:moltrust:.+} never matched a foreign "
              "method, so it produced a bare 404 instead. Found on 2026-10-06 "
              "while fixing the encoding, and this vector is why it cannot go "
              "back to being dead code.")

# --- the running service against the version it claims --------------------
add(name="the running driver behaves like the version it reports",
    description="/health must name the commit the image was built from, and the "
                "malformed identifier must answer invalidDid. Two codebases both "
                "reported 1.0.0 and answered differently.",
    section_ref="2.2", check="deployment", target="driver",
    input={"did": "did:moltrust:ambassador0001"},
    expected={"result": "CONFORMS"},
    rationale="A deployment is conformant when what runs can be named and the "
              "name matches the behaviour. Until 2026-10-06 the service at "
              "uresolver.moltrust.ch ran server.js from a second repository, "
              "reported version 1.0.0, and answered notFound where the "
              "specification requires a malformed identifier to be refused as "
              "such. This vector is what makes the register entry closable: it "
              "cannot be closed by inspection, only by the service answering "
              "correctly and saying which commit answered.",
    )

OUT.mkdir(exist_ok=True)


def main():
    want = {}
    for v in vectors:
        # The file is named by the id, so a report that names one leads straight
        # to the file.
        want[f"{v['id']}.json"] = json.dumps(v, indent=2, ensure_ascii=False) + "\n"

    if "--check" in sys.argv:
        have = {p.name: p.read_text() for p in OUT.glob("*.json")}
        if have != want:
            only_disk = sorted(set(have) - set(want))
            only_table = sorted(set(want) - set(have))
            changed = sorted(k for k in set(have) & set(want) if have[k] != want[k])
            print(f"vectors/ weicht von der Tabelle ab: "
                  f"{len(only_disk)} nur auf der Platte, {len(only_table)} nur in der "
                  f"Tabelle, {len(changed)} geaendert", file=sys.stderr)
            for k in only_disk + only_table + changed:
                print(f"  {k}", file=sys.stderr)
            return 1
        print(f"vectors/ stimmt mit der Tabelle: {len(want)} Vektoren")
        return 0

    for p in OUT.glob("*.json"):
        p.unlink()
    for name, body in want.items():
        (OUT / name).write_text(body)
    print(f"{len(want)} Vektoren nach {OUT}")
    by = {}
    for v in vectors:
        by[v["check"]] = by.get(v["check"], 0) + 1
    print(f"  nach Pruefart: {by}")
    print(f"  mit bekannter Abweichung: "
          f"{sum(1 for v in vectors if 'known_deviation' in v)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
