#!/usr/bin/env python3
"""Reject drift in the pinned SDK source or its exact extracted static bodies."""
import hashlib
import json
from pathlib import Path
import argparse


def extract_function(text, name, return_type):
    # Restricted extraction of these pinned, brace-balanced C bodies; not a C parser.
    start = text.index("static " + return_type + " " + name + "(")
    end = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return (text[start:end] + "\n").encode()


def verify_suite(suite):
    if suite not in ("policy_selection", "strong_mix"):
        raise ValueError("unknown business suite")
    here = Path(__file__).resolve().parent
    root = here.parent.parent
    directory = here / "suites" / suite
    manifest = json.loads((directory / "sources.json").read_text())
    source = root / manifest["source"]
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    if digest(source) != manifest["source_sha256"]:
        raise ValueError("Business source SHA-256 mismatch: " + str(source))
    body = extract_function(source.read_text(), manifest["function"], manifest["return_type"])
    if body != (directory / "body.inc").read_bytes() or digest(directory / "body.inc") != manifest["body_sha256"]:
        raise ValueError("Business function body drift")
    for segment in manifest["segments"]:
        text = (root / segment["source"]).read_text()
        if "function" in segment:
            expected = extract_function(text, segment["function"], segment["return_type"])
        else:
            start = text.index(segment["start"])
            expected = (text[start:text.index(segment["end"], start)].rstrip() + "\n").encode()
        file = directory / segment["file"]
        if file.read_bytes() != expected or digest(file) != segment["sha256"]:
            raise ValueError("Business dependency extraction drift: " + str(file))
    for dep in manifest["dependencies"]:
        if digest(root / dep["path"]) != dep["sha256"]:
            raise ValueError("Business dependency SHA-256 mismatch")
    constants = directory / "constants.inc"
    if digest(constants) != manifest["constants_sha256"]:
        raise ValueError("Business constants drift")
    origin = (root / manifest["dependencies"][0]["path"]).read_text() if suite == "policy_selection" else source.read_text()
    for line in constants.read_text().splitlines():
        if line not in origin.splitlines():
            raise ValueError("Extracted constant missing from original source")
    return manifest

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("gf2", "policy_selection", "strong_mix"), default="gf2")
    args = parser.parse_args()
    print(json.dumps(verify() if args.suite == "gf2" else verify_suite(args.suite), sort_keys=True))
