#!/usr/bin/env python3
"""Check every vector against schema/vector-schema.json.

Standard library only, so CI needs no install step. This covers the parts of
JSON Schema the vector schema actually uses — required, type, enum, pattern,
minLength, minimum/maximum and additionalProperties — and refuses anything it
does not understand rather than passing it silently.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "vector-schema.json").read_text())
VECTORS = ROOT / "vectors"

TYPES = {"object": dict, "array": list, "string": str, "integer": int,
         "number": (int, float), "boolean": bool, "null": type(None)}

KNOWN = {"type", "enum", "pattern", "minLength", "minimum", "maximum",
         "required", "properties", "additionalProperties", "items",
         "description", "default", "$schema", "$id", "title"}


def type_ok(value, spec):
    want = spec if isinstance(spec, list) else [spec]
    for w in want:
        t = TYPES.get(w)
        if t is None:
            return False
        if w == "integer" and isinstance(value, bool):
            continue
        if w in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, t):
            return True
    return False


def validate(value, schema, path, errors):
    unknown = set(schema) - KNOWN
    if unknown:
        errors.append(f"{path}: Schema benutzt {sorted(unknown)}, "
                      "das dieser Pruefer nicht kennt")
        return

    if "type" in schema and not type_ok(value, schema["type"]):
        errors.append(f"{path}: Typ {type(value).__name__}, erwartet {schema['type']}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} nicht in {schema['enum']}")
    if "pattern" in schema and isinstance(value, str) \
            and not re.search(schema["pattern"], value):
        errors.append(f"{path}: {value!r} passt nicht auf {schema['pattern']}")
    if "minLength" in schema and isinstance(value, str) \
            and len(value) < schema["minLength"]:
        errors.append(f"{path}: kuerzer als {schema['minLength']}")
    if "minimum" in schema and isinstance(value, (int, float)) \
            and not isinstance(value, bool) and value < schema["minimum"]:
        errors.append(f"{path}: {value} < {schema['minimum']}")
    if "maximum" in schema and isinstance(value, (int, float)) \
            and not isinstance(value, bool) and value > schema["maximum"]:
        errors.append(f"{path}: {value} > {schema['maximum']}")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: {key} fehlt")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(props))
            if extra:
                errors.append(f"{path}: unerlaubte Member {extra}")
        for key, sub in props.items():
            if key in value:
                validate(value[key], sub, f"{path}.{key}", errors)
    elif isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            validate(item, schema["items"], f"{path}[{i}]", errors)


def main():
    files = sorted(VECTORS.glob("*.json"))
    if not files:
        print("keine Vektoren in vectors/", file=sys.stderr)
        return 2
    bad, ids = 0, {}
    for f in files:
        try:
            vec = json.loads(f.read_text())
        except json.JSONDecodeError as e:
            print(f"  {f.name}: kein JSON ({e})", file=sys.stderr)
            bad += 1
            continue
        errors = []
        validate(vec, SCHEMA, f.name, errors)
        # An id must identify exactly one vector.
        vid = vec.get("id")
        if vid in ids:
            errors.append(f"{f.name}: id {vid} schon in {ids[vid]}")
        ids[vid] = f.name
        # A resolve or bridge vector needs a target that answers.
        if vec.get("check") in ("resolve", "bridge") and vec.get("target") in (None, "none"):
            errors.append(f"{f.name}: check {vec['check']} ohne Ziel")
        if vec.get("check") == "syntax" and vec.get("target") not in (None, "none"):
            errors.append(f"{f.name}: ein Syntax-Vektor braucht kein Ziel")
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        bad += bool(errors)
    if bad:
        print(f"{bad} von {len(files)} Vektoren fehlerhaft", file=sys.stderr)
        return 1
    print(f"{len(files)} Vektoren erfuellen das Schema")
    return 0


if __name__ == "__main__":
    sys.exit(main())
