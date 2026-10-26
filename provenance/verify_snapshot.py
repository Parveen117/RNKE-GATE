#!/usr/bin/env python3
"""Verify a dated snapshot against Git objects without running repository code."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def verify(snapshot, repo):
    raw = snapshot.read_bytes()
    expected_digest = snapshot.with_suffix(".sha256").read_text().split()[0]
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError("Snapshot SHA-256 mismatch")
    data = json.loads(raw)
    commit = data["baseline_commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid baseline commit")
    tree = git(repo, "rev-parse", commit + "^{tree}").decode().strip()
    if tree != data["baseline_tree"]:
        raise ValueError("Baseline tree mismatch")
    observed = []
    for item in git(repo, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        if not item:
            continue
        metadata, path = item.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        record = {"path": path.decode(), "mode": mode, "git_object_type": kind,
                  "git_object_sha1": oid}
        if kind == "blob":
            content = git(repo, "cat-file", "blob", oid)
            record.update(size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        observed.append(record)
    observed.sort(key=lambda x: x["path"])
    if observed != data["files"]:
        raise ValueError("File inventory or content hashes differ from the snapshot")
    return len(observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=pathlib.Path,
                        default=pathlib.Path("provenance/2026-10-26/baseline.json"))
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()
    try:
        count = verify(args.snapshot, args.repo)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, "FAIL: " + str(exc) + "\n")
    print(f"PASS: {count} Git entries match the recorded baseline and SHA-256 hashes.")
    print("This verifies content identity, not scientific validity or legal priority.")


if __name__ == "__main__":
    main()
