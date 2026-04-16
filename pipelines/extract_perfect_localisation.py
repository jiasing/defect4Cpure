"""
extract_perfect_localisation.py

For each of the 52 CVE test cases, extract:
  - category: single_line | single_hunk | multi_hunk
  - changed_lines: list of {line_in_func, content} for every line in the
    buggy function that needs to change

Line numbers are 1-indexed relative to the first line of the buggy function,
matching exactly what the LLM sees when given the 'buggy' field.

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

def parse_changed_abs_lines(patch_text):
    """
    Parse a unified diff patch and return the set of absolute line numbers
    in the ORIGINAL (buggy) file that were removed or are the insertion point
    for pure additions.

    For removed lines (-): record their absolute position.
    For pure-addition hunks (no - lines): record the last context line before
    the insertion as the insertion point.
    """
    changed = set()
    current_orig_line = None

    for raw_line in patch_text.splitlines():
        hunk_match = re.match(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", raw_line)
        if hunk_match:
            current_orig_line = int(hunk_match.group(1))
            continue

        if current_orig_line is None:
            continue

        if raw_line.startswith("-"):
            changed.add(current_orig_line)
            current_orig_line += 1
        elif raw_line.startswith("+"):
            # pure addition — record preceding context line as insertion point
            # (only if nothing was removed in this hunk yet at this position)
            pass  # insertion point tracked separately below
        else:
            # context line
            current_orig_line += 1

    # Second pass: also capture insertion points for pure-addition hunks
    current_orig_line = None
    last_context_line = None
    in_hunk_had_removal = False

    for raw_line in patch_text.splitlines():
        hunk_match = re.match(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", raw_line)
        if hunk_match:
            current_orig_line = int(hunk_match.group(1))
            in_hunk_had_removal = False
            last_context_line = None
            continue

        if current_orig_line is None:
            continue

        if raw_line.startswith("-"):
            in_hunk_had_removal = True
            current_orig_line += 1
        elif raw_line.startswith("+"):
            if not in_hunk_had_removal and last_context_line is not None:
                changed.add(last_context_line)
        else:
            last_context_line = current_orig_line
            current_orig_line += 1

    return changed


# ── Main extraction ────────────────────────────────────────────────────────────

def extract_changed_lines(bug_id, cve_data, sha_to_patches):
    sha = bug_id.split("@")[-1]

    # ── API metadata ──────────────────────────────────────────────────────────
    defect    = get_defect(bug_id)
    meta      = defect["additional_info"]["metadata"]
    loc       = meta["files"]["src0_location"]
    src_files = meta["files"]["src"]

    func_start     = loc["func_start"]
    hunk_start     = loc["hunk_start"]
    hunk_end       = loc["hunk_end"]
    line_number    = loc["line_number"]
    line_is_single = loc["line_is_single"]
    hunk_is_single = loc["hunk_is_single"]

    # ── Buggy function text ───────────────────────────────────────────────────
    src_basenames = [os.path.basename(f) for f in src_files]
    entries = cve_data.get(sha, [])
    matched = [(k, v) for k, v in entries if any(b in k for b in src_basenames)]
    _, entry = matched[0]
    buggy_text  = entry["buggy"]
    buggy_lines = buggy_text.splitlines()  # 0-indexed; line_in_func = index+1

    def abs_to_rel(abs_line):
        return abs_line - func_start + 1

    def rel_content(rel_line):
        idx = rel_line - 1
        if 0 <= idx < len(buggy_lines):
            return buggy_lines[idx]
        return ""

    # ── Determine changed relative line numbers ───────────────────────────────
    if line_is_single and line_number is not None:
        category = "single_line"
        rel_lines = [abs_to_rel(line_number)]

    elif hunk_is_single and hunk_start is not None:
        category = "single_hunk"
        rel_lines = list(range(abs_to_rel(hunk_start), abs_to_rel(hunk_end) + 1))

    else:
        # multi_hunk: parse git patch for the primary src file
        category = "multi_hunk"
        patches  = sha_to_patches.get(sha, {})

        # Find the patch for the primary src file
        src_patch = None
        for filename, patch_text in patches.items():
            if any(b in filename for b in src_basenames):
                src_patch = patch_text
                break

        if src_patch:
            abs_changed = parse_changed_abs_lines(src_patch)
            # Keep only lines within the function bounds
            func_end = loc["func_end"] or max(abs_changed, default=func_start)
            abs_in_func = {l for l in abs_changed if func_start <= l <= func_end}
            rel_lines = sorted(abs_to_rel(l) for l in abs_in_func)
        else:
            rel_lines = []

    # ── Build output ──────────────────────────────────────────────────────────
    changed_lines = [
        {"line_in_func": r, "content": rel_content(r)}
        for r in rel_lines
    ]

    return {
        "bug_id":       bug_id,
        "category":     category,
        "func_lines":   len(buggy_lines),
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
