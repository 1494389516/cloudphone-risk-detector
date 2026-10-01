#!/usr/bin/env python3
"""Reject drift in the pinned SDK source or its exact extracted static bodies."""
import hashlib
import json
from pathlib import Path

def verify():
    directory = Path(__file__).resolve().parent
    manifest = json.loads((directory / "sources.json").read_text())
    source = (directory.parent.parent / manifest["source"]).read_bytes()
    if hashlib.sha256(source).hexdigest() != manifest["source_sha256"]:
        raise ValueError("Pinned SDK source SHA-256 mismatch")
    text = source.decode("utf-8")
    bodies = []
    for name in manifest["functions"]:
        start = text.index("static uint64_t " + name + "(")
        end = text.index("{", start) + 1
        depth = 1
        while depth:
            depth += (text[end] == "{") - (text[end] == "}")
            end += 1
        bodies.append(text[start:end])
    extracted = ("\n\n".join(bodies) + "\n").encode()
    if extracted != (directory / "gf2_candidates.inc").read_bytes():
        raise ValueError("Extracted SDK function bodies differ from pinned source")
    if hashlib.sha256(extracted).hexdigest() != manifest["extracted_sha256"]:
        raise ValueError("Extracted function SHA-256 mismatch")
    return manifest

if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
