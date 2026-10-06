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
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors"

# A key used only here, so the derivation vector carries a real Ed25519 public
# key rather than a made-up hex string. Generated once, never a signing key.
SAMPLE_PUBKEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"


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

FOREIGN = [
    ("did:example:0123456789abcdef", "a method this registry does not serve"),
    ("did:key:z6MkhaXgBZDvotDkL5257faiz", "did:key"),
    ("did:aps:ef8bbf57911681e4a2965ee6", "did:aps, a peer ecosystem"),
]

vectors = []
n = 0


def add(**kw):
    global n
    n += 1
    kw["id"] = f"did-vector-{n:03d}"
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

add(name="a registered DID derives from its own published key",
    description="For every DID the registry resolves with a publicKeyHex, the "
                "method-specific identifier must be the first 8 bytes of "
                "SHA-256 over that key.",
    section_ref="2.2", check="derivation", target="api",
    input={"did": "did:moltrust:d34ed796a4dc4698"},
    expected={"result": "CONFORMS"},
    rationale="Section 2.2 ties the identifier to the key. A registry that "
              "issues identifiers from another source produces DIDs that cannot "
              "be checked against their own key material.",
    known_deviation="derivation::identifiers are not derived from the key")

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

for did, why in FOREIGN:
    add(name=f"a foreign method is refused as such: {why}",
        description=f"{did} is not a did:moltrust identifier.",
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


def slug(v):
    return v["name"].lower().replace(":", "").replace(",", "").replace("'", "") \
        .replace("(", "").replace(")", "").replace(" ", "-")[:58].strip("-")


def main():
    want = {}
    for v in vectors:
        want[f"{v['id']}-{slug(v)}.json"] = json.dumps(v, indent=2, ensure_ascii=False) + "\n"

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
