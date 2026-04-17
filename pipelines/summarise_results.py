"""
summarise_results.py — aggregate statistics from all ablation pipeline txt files.

Searches the pipelines directory for every .txt file produced by the ablation
pipeline (both full runs and single test_ablation runs), parses out the key
fields, and writes a summary JSON + prints a table to stdout.
"""

import json
import re
import sys
from pathlib import Path

PIPELINES_DIR = Path(__file__).parent

# ── Patterns ─────────────────────────────────────────────────────────────────

# Header fields
RE_TIMESTAMP  = re.compile(r"Timestamp\s*:\s*(.+)")
RE_MODEL      = re.compile(r"Model\s*:\s*(.+)")
RE_ABLATION   = re.compile(r"Ablation\s*:\s*(.+)")
RE_JIN_AUG    = re.compile(r"JIN augmentation\s*:\s*(.+)")
RE_TOTAL_CASES = re.compile(r"Total CVE cases\s*:\s*(\d+)")

# Overall results block (full run)
RE_OVERALL_TOTAL   = re.compile(r"Total cases\s*:\s*(\d+)")
RE_OVERALL_COMPILE = re.compile(r"Compile Rate\s*:\s*(\d+)\s*/\s*(\d+)")
RE_OVERALL_PASS    = re.compile(r"Pass@(\d+)\s*:\s*(\d+)\s*/\s*(\d+)")

# Header k value
RE_CANDIDATES_K = re.compile(r"Candidates\s*\(k\)\s*:\s*(\d+)")

# Single-test result block
RE_SINGLE_COMPILE = re.compile(r"Compile Rate\s*:\s*(\d+)\s*/\s*1")
RE_SINGLE_PASS    = re.compile(r"Pass@(\d+)\s*:\s*(\d+)\s*/\s*1")

# Per-case results (used when no OVERALL block is present as fallback)
RE_CASE_COMPILE = re.compile(r"^Compile\s*:\s*(True|False)", re.MULTILINE)
RE_CASE_FIXED   = re.compile(r"^Fixed\s*:\s*(True|False)", re.MULTILINE)


def parse_file(path: Path) -> dict | None:
    text = path.read_text(errors="replace")

    # Determine file type
    is_full_run  = "OVERALL RESULTS" in text
    is_test_run  = "TEST ABLATION RUN" in text and not is_full_run

    result = {
        "file": path.name,
        "timestamp": None,
        "model": None,
        "ablation": None,
        "jin_augmentation": None,
        "k": None,
        "total_cases": None,
        "compiled": None,
        "fixed": None,
        "compile_rate_pct": None,
        "pass_at_k_pct": None,
    }

    # Header fields
    if m := RE_TIMESTAMP.search(text):
        result["timestamp"] = m.group(1).strip()
    if m := RE_MODEL.search(text):
        result["model"] = m.group(1).strip()
    if m := RE_ABLATION.search(text):
        result["ablation"] = m.group(1).strip()
    if m := RE_JIN_AUG.search(text):
        result["jin_augmentation"] = m.group(1).strip()
    if m := RE_TOTAL_CASES.search(text):
        result["total_cases"] = int(m.group(1))
    if m := RE_CANDIDATES_K.search(text):
        result["k"] = int(m.group(1))

    if is_full_run:
        # Parse the OVERALL RESULTS block
        block_start = text.find("OVERALL RESULTS")
        block = text[block_start:]
        if m := RE_OVERALL_TOTAL.search(block):
            result["total_cases"] = int(m.group(1))
        if m := RE_OVERALL_COMPILE.search(block):
            compiled, total = int(m.group(1)), int(m.group(2))
            result["compiled"] = compiled
            result["total_cases"] = result["total_cases"] or total
            result["compile_rate_pct"] = round(compiled / total * 100, 1) if total else None
        if m := RE_OVERALL_PASS.search(block):
            k, fixed, total = int(m.group(1)), int(m.group(2)), int(m.group(3))
            result["k"] = result["k"] or k
            result["fixed"] = fixed
            result["pass_at_k_pct"] = round(fixed / total * 100, 1) if total else None

    elif is_test_run:
        # Single test run — parse the RESULT block
        block_start = text.rfind("RESULT")
        block = text[block_start:]
        total = 1
        result["total_cases"] = 1
        if m := RE_SINGLE_COMPILE.search(block):
            result["compiled"] = int(m.group(1))
            result["compile_rate_pct"] = float(m.group(1)) * 100
        if m := RE_SINGLE_PASS.search(block):
            result["k"] = result["k"] or int(m.group(1))
            result["fixed"] = int(m.group(2))
            result["pass_at_k_pct"] = float(m.group(2)) * 100

    else:
        # Fallback: count Compile/Fixed lines
        compiles = RE_CASE_COMPILE.findall(text)
        fixes    = RE_CASE_FIXED.findall(text)
        if compiles:
            result["total_cases"] = result["total_cases"] or len(compiles)
            result["compiled"]    = sum(1 for v in compiles if v == "True")
            result["fixed"]       = sum(1 for v in fixes    if v == "True")
            total = len(compiles)
            result["compile_rate_pct"] = round(result["compiled"] / total * 100, 1) if total else None
            result["pass_at_k_pct"]    = round(result["fixed"]    / total * 100, 1) if total else None

    return result


def collect_all(experiment_folder: str | None = None) -> list[dict]:
    if experiment_folder:
        search_dir = PIPELINES_DIR / "experiments" / experiment_folder
    else:
        search_dir = PIPELINES_DIR
    files = sorted(search_dir.glob("*.txt"))
    results = []
    for f in files:
        parsed = parse_file(f)
        if parsed:
            results.append(parsed)
    return results


def print_table(results: list[dict]) -> None:
    col_file     = max(len(r["file"]) for r in results)
    col_model    = max((len(r["model"] or "") for r in results), default=5)
    col_ablation = max((len(r["ablation"] or "") for r in results), default=8)

    ks = [r["k"] for r in results if r["k"] is not None]
    k_label = f"Pass@{ks[0]}%" if ks else "Pass@k%"

    header = (
        f"{'File':<{col_file}}  "
        f"{'Model':<{col_model}}  "
        f"{'Ablation':<{col_ablation}}  "
        f"{'Cases':>5}  "
        f"{'Compiled':>8}  "
        f"{'Fixed':>5}  "
        f"{'Compile%':>8}  "
        f"{k_label:>8}"
    )
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)

    for r in results:
        print(
            f"{r['file']:<{col_file}}  "
            f"{(r['model'] or ''):<{col_model}}  "
            f"{(r['ablation'] or ''):<{col_ablation}}  "
            f"{(r['total_cases'] if r['total_cases'] is not None else '?'):>5}  "
            f"{(r['compiled'] if r['compiled'] is not None else '?'):>8}  "
            f"{(r['fixed'] if r['fixed'] is not None else '?'):>5}  "
            f"{('{:.1f}'.format(r['compile_rate_pct']) if r['compile_rate_pct'] is not None else '?'):>8}  "
            f"{('{:.1f}'.format(r['pass_at_k_pct']) if r['pass_at_k_pct'] is not None else '?'):>8}"
        )

    print(sep)


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else None
    results = collect_all(folder)

    search_dir = (PIPELINES_DIR / "experiments" / folder) if folder else PIPELINES_DIR
    if not results:
        print("No .txt files found in", search_dir)
        sys.exit(1)

    # Save JSON
    out_json = PIPELINES_DIR / "ablation_summary.json"
    out_json.write_text(json.dumps(results, indent=2))

    # Print table
    print(f"\nAblation results — {len(results)} file(s) found\n")
    print_table(results)
    print(f"\nSaved to {out_json}\n")


if __name__ == "__main__":
    main()
