"""
extract_perfect_localisation.py

For each of the 52 CVE test cases, extract:
  - category: single_line | single_hunk | multi_hunk
  - changed_lines: list of {line_in_func, content} for every line in the
    buggy function that needs to change

Line numbers are 1-indexed relative to the first line of the buggy function,
matching exactly what the LLM sees when given the 'buggy' field.

All categories drive off git patch parsing so that only actually-modified lines
are reported (not entire hunk regions including context lines).

Output: perfect_localisation.json
"""

import json
import os
import re
import urllib.request
from pathlib import Path

DEFECTS4C_URL = "http://127.0.0.1:80"
CVE_DATA_DIR  = Path("/src/data/buggy_errmsg_cve")
GIT_API_PATH  = Path("/src/data/github_api_save.jsonl")


# ── Load data ─────────────────────────────────────────────────────────────────

def load_cve_data():
    """sha -> list of (key, entry) from all 3 CVE JSON files."""
    cve_data = {}
    for fname in [
        "single_function_repair.json",
        "single_function_single_hunk_repair.json",
        "single_function_single_line_repair.json",
    ]:
        with open(CVE_DATA_DIR / fname) as f:
            d = json.load(f)
        for k, v in d.items():
            sha = k.split("___")[0]
            cve_data.setdefault(sha, []).append((k, v))
    return cve_data


def load_git_patches():
    """sha -> {filename: patch_text} from github_api_save.jsonl."""
    sha_to_patches = {}
    with open(GIT_API_PATH) as f:
        for line in f:
            r = json.loads(line)
            content = json.loads(r["content"])
            sha = content["sha"]
            patches = {}
            for fi in content.get("files", []):
                if fi.get("patch"):
                    patches[fi["filename"]] = fi["patch"]
            sha_to_patches[sha] = patches
    return sha_to_patches


def get_52_cve_ids(cve_data):
    cve_shas = set(cve_data.keys())
    resp = urllib.request.urlopen(f"{DEFECTS4C_URL}/list_defects_bugid").read()
    all_ids = json.loads(resp)["defects"]
    return [b for b in all_ids if b.split("@")[-1] in cve_shas]


def get_defect(bug_id):
    resp = urllib.request.urlopen(f"{DEFECTS4C_URL}/get_defect/{bug_id}").read()
    return json.loads(resp)


# ── Git patch parsing ──────────────────────────────────────────────────────────

def _removed_line_contents(patch_text):
    """
    Return the stripped content of every line removed (-) in the patch.
    Used for string-matching against the buggy function text in multi_hunk cases.
    """
    removed = []
    for raw in patch_text.splitlines():
        if raw.startswith("-") and not raw.startswith("---"):
            removed.append(raw[1:])  # strip leading '-', keep rest verbatim
    return removed


# ── Main extraction ────────────────────────────────────────────────────────────

def extract_changed_lines(bug_id, cve_data, sha_to_patches):
    sha = bug_id.split("@")[-1]

    # ── API metadata ──────────────────────────────────────────────────────────
    defect    = get_defect(bug_id)
    meta      = defect["additional_info"]["metadata"]
    loc       = meta["files"]["src0_location"]
    src_files = meta["files"]["src"]

    line_is_single = loc["line_is_single"]
    hunk_is_single = loc["hunk_is_single"]

    if line_is_single:
        category = "single_line"
    elif hunk_is_single:
        category = "single_hunk"
    else:
        category = "multi_hunk"

    # ── Buggy function text ───────────────────────────────────────────────────
    src_basenames = [os.path.basename(f) for f in src_files]
    entries = cve_data.get(sha, [])
    matched = [(k, v) for k, v in entries if any(b in k for b in src_basenames)]
    _, entry = matched[0]
    buggy_text  = entry["buggy"]
    buggy_lines = buggy_text.splitlines()  # 0-indexed; line_in_func = index+1

    def rel_content(rel_line):
        idx = rel_line - 1
        if 0 <= idx < len(buggy_lines):
            return buggy_lines[idx]
        return ""

    # ── Determine changed lines using prefix for single_line / single_hunk ──────
    # The CVE JSON guarantees: buggy == prefix + buggy_hunk_masked + suffix.
    # So the masked region starts at len(prefix.splitlines()) + 1 (1-indexed).
    # This is always consistent with what the LLM sees in the buggy text and
    # avoids the API func_start offset (which tracks the hunk boundary, not
    # the actual function start).

    prefix_lines = entry.get("prefix", "").splitlines()
    masked_text  = entry.get("buggy_hunk_masked", "") or ""
    masked_lines = masked_text.splitlines()

    rel_lines = []

    if category in ("single_line", "single_hunk"):
        masked_start = len(prefix_lines) + 1          # 1-indexed
        masked_end   = masked_start + len(masked_lines) - 1
        rel_lines = list(range(masked_start, masked_end + 1))

    else:
        # multi_hunk: primary masked region from prefix + string-match any
        # additional changed lines from the git patch against the buggy text.

        # Primary region
        masked_start = len(prefix_lines) + 1
        masked_end   = masked_start + len(masked_lines) - 1
        primary = set(range(masked_start, masked_end + 1))

        # Git patch: find additional changed lines via content matching
        patches   = sha_to_patches.get(sha, {})
        src_patch = None
        for filename, patch_text in patches.items():
            if any(b in filename for b in src_basenames):
                src_patch = patch_text
                break

        extra = set()
        if src_patch:
            removed_contents = _removed_line_contents(src_patch)
            for content in removed_contents:
                for i, bl in enumerate(buggy_lines):
                    if bl == content and (i + 1) not in primary:
                        extra.add(i + 1)

        rel_lines = sorted(primary | extra)

    # ── Build output ──────────────────────────────────────────────────────────
    changed_lines = [
        {"line_in_func": r, "content": rel_content(r)}
        for r in rel_lines
    ]

    return {
        "bug_id":        bug_id,
        "category":      category,
        "func_lines":    len(buggy_lines),
        "changed_lines": changed_lines,
    }


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print("Loading data...")
    cve_data      = load_cve_data()
    sha_to_patches = load_git_patches()
    cve_ids        = get_52_cve_ids(cve_data)

    print(f"Processing {len(cve_ids)} CVE cases...")
    results = []
    for i, bug_id in enumerate(cve_ids, 1):
        print(f"  [{i:02d}/{len(cve_ids)}] {bug_id}")
        result = extract_changed_lines(bug_id, cve_data, sha_to_patches)
        results.append(result)

    out_path = Path(__file__).parent / "perfect_localisation.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nDone. Written to {out_path}")

    # Summary
    from collections import Counter
    cats = Counter(r["category"] for r in results)
    print(f"  single_line : {cats['single_line']}")
    print(f"  single_hunk : {cats['single_hunk']}")
    print(f"  multi_hunk  : {cats['multi_hunk']}")
    no_lines = [r["bug_id"] for r in results if not r["changed_lines"]]
    if no_lines:
        print(f"  WARNING — {len(no_lines)} cases with empty changed_lines:")
        for b in no_lines:
            print(f"    {b}")


if __name__ == "__main__":
    main()
