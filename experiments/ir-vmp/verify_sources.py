#!/usr/bin/env python3
"""Reject drift in the pinned SDK source or its exact extracted static bodies."""
import hashlib
import json
from pathlib import Path
import argparse


def _skip_string(text, index):
    """Return the index just past a string/char literal starting at ``index``.

    Handles backslash escapes. A char literal is never allowed to span a
    newline; an unterminated quote bails at end-of-input so the caller fails
    closed instead of looping.
    """
    quote = text[index]
    index += 1
    while index < len(text):
        char = text[index]
        if char == '\\':
            index += 2
            continue
        if char == quote:
            return index + 1
        if char == '\n' and quote == "'":
            return index
        index += 1
    return index


def extract_function(text, name, return_type):
    """Extract one pinned, brace-balanced C function body.

    NOT a C parser: this is a restricted lexical scanner for the pinned
    sources only. It counts braces while SKIPPING string literals, char
    literals, ``//`` line comments and ``/* */`` block comments, so braces
    inside them no longer misalign the end of the function (the previous
    naive counter truncated at the first ``}`` in a string/comment).
    Remaining limitations, stated explicitly: it does not understand
    preprocessor conditionals that change brace balance, trigraphs, line
    continuations inside comments, or C23 digit separators (``'``) in code.
    Pinned sources are hash-pinned, so any such drift fails verification
    instead of being silently mis-extracted.
    """
    start = text.index("static " + return_type + " " + name + "(")
    end = text.index("{", start) + 1
    depth = 1
    index = end
    while depth:
        char = text[index]
        if char in ('"', "'"):
            index = _skip_string(text, index)
            continue
        if char == '/' and index + 1 < len(text) and text[index + 1] == '/':
            newline = text.find('\n', index)
            index = len(text) if newline < 0 else newline + 1
            continue
        if char == '/' and index + 1 < len(text) and text[index + 1] == '*':
            close = text.find('*/', index + 2)
            index = len(text) if close < 0 else close + 2
            continue
        depth += (char == "{") - (char == "}")
        index += 1
    return (text[start:index] + "\n").encode()


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
        # Same string/comment-aware scanner as extract_function; do not
        # duplicate a second naive brace counter here.
        bodies.append(extract_function(text, name, "uint64_t").decode("utf-8").rstrip("\n"))
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
