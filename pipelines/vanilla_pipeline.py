import argparse
import json
import requests
import time
import os
from datetime import datetime
from pathlib import Path
from openai import OpenAI

# ── Constants ─────────────────────────────────────────────────────────────────
DEFECTS4C_BASE_URL = "http://127.0.0.1:11111"

CVE_DATA_DIR = Path("defectsc_tpl/data/buggy_errmsg_cve")
CVE_DATA_FILES = [
    "single_function_repair.json",
    "single_function_single_hunk_repair.json",
    "single_function_single_line_repair.json",
]


def load_cve_shas() -> set[str]:
    """Return the set of SHAs present in the local CVE data files."""
    shas: set[str] = set()
    for fname in CVE_DATA_FILES:
        data = json.load(open(CVE_DATA_DIR / fname))
        for key in data:
            shas.add(key.split("___")[0])
    return shas


def process_defect(bug_id: str, model: str, client: OpenAI) -> dict:
    """
    Run the full pipeline for one defect.
    Returns a result dict with keys:
        bug_id, patch_built, fixed, return_code, error
    """
    result = {
        "bug_id":      bug_id,
        "patch_built": False,
        "fixed":       False,
        "return_code": None,
        "error":       "",
    }

    # Step 1: Get defect info and prompt
    response = requests.get(f"{DEFECTS4C_BASE_URL}/get_defect/{bug_id}")
    defect_data = response.json()
    if defect_data.get("status") != "success":
        result["error"] = f"get_defect failed: {defect_data}"
        return result

    prompts     = defect_data["prompt_data"]["prompt"]
    temperature = defect_data["prompt_data"].get("temperature", 0.7)

    # Step 2: Send to LLM
    try:
        ai_response = client.chat.completions.create(
            model=model,
            messages=prompts,
            temperature=temperature,
            max_tokens=4096,
        )
        llm_response = ai_response.choices[0].message.content
    except Exception as e:
        result["error"] = f"LLM error: {e}"
        return result

    print(f"  LLM response: {llm_response[:80].strip()}...")

    # Step 3: Build patch
    patch_response = requests.post(
        f"{DEFECTS4C_BASE_URL}/build_patch",
        headers={"Content-Type": "application/json"},
        json={
            "bug_id":        bug_id,
            "llm_response":  llm_response,
            "method":        "direct",
            "generate_diff": True,
            "persist_flag":  True,
        },
    )
    patch_data = patch_response.json()

    if not patch_data.get("success"):
        result["error"] = f"build_patch failed: {patch_data.get('detail', patch_data)}"
        return result

    result["patch_built"] = True
    patch_path = patch_data["fix_p"]
    print(f"  Patch created: {patch_path}")

    # Step 4: Submit fix
    fix_response = requests.post(
        f"{DEFECTS4C_BASE_URL}/fix",
        headers={"Content-Type": "application/json"},
        json={"bug_id": bug_id, "patch_path": patch_path},
    )
    fix_data = fix_response.json()
    if "handle" not in fix_data:
        result["error"] = f"fix submission failed: {fix_data}"
        return result

    handle = fix_data["handle"]

    # Step 5: Poll for result
    max_wait      = 300
    poll_interval = 10
    start_time    = time.time()

    while time.time() - start_time < max_wait:
        status_data = requests.get(f"{DEFECTS4C_BASE_URL}/status/{handle}").json()
        current = status_data.get("status", "unknown")
        if current in ("completed", "failed"):
            rc = status_data.get("return_code", -1)
            result["return_code"] = rc
            if rc == 0:
                result["fixed"] = True
            else:
                result["error"] = status_data.get("error", "")[:200]
            return result
        time.sleep(poll_interval)

    result["error"] = "timed out"
    return result


def main():
    parser = argparse.ArgumentParser(description="Defects4C LLM repair pipeline")
    parser.add_argument(
        "--model",
        default=os.getenv("OLLAMA_MODEL"),
        help="Ollama model name (e.g. llama3:8b). Also read from OLLAMA_MODEL env var.",
    )
    parser.add_argument(
        "--run-label",
        default=None,
        help="Label used in the output filename and summary. Defaults to the model name.",
    )
    parser.add_argument(
        "--ollama-host",
        default=os.getenv("OLLAMA_HOST", "http://100.97.159.90:11434"),
        help="Ollama host URL. Also read from OLLAMA_HOST env var.",
    )
    args = parser.parse_args()

    if not args.model:
        parser.error("--model is required (or set OLLAMA_MODEL env var)")

    run_label = args.run_label or args.model.replace(":", "-")
    run_dt    = datetime.now()
    out_file  = f"{run_label}_{run_dt.strftime('%Y%m%d_%H%M%S')}.txt"

    client = OpenAI(
        api_key="ollama",
        base_url=f"{args.ollama_host}/v1/",
    )

    print(f"Run: {run_label}  |  {run_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Model: {args.model}")
    print(f"Output: {out_file}")
    print()

    # Load CVE SHA set and filter server defect list to the 52 CVE cases
    cve_shas = load_cve_shas()
    all_ids  = requests.get(f"{DEFECTS4C_BASE_URL}/list_defects_bugid").json()["defects"]
    cve_ids  = [b for b in all_ids if b.split("@")[-1] in cve_shas]
    total    = len(cve_ids)
    print(f"CVE vulnerability test cases: {total}")
    print("=" * 60)

    results = []

    for i, bug_id in enumerate(cve_ids, 1):
        print(f"\n[{i}/{total}] {bug_id}")
        result = process_defect(bug_id, args.model, client)
        results.append(result)

        if result["fixed"]:
            print("  FIXED")
        elif result["patch_built"]:
            print(f"  patch built, fix failed (rc={result['return_code']})")
        else:
            print(f"  patch failed: {result['error'][:100]}")

    # ── Summary ───────────────────────────────────────────────────────────────
    n_patch = sum(1 for r in results if r["patch_built"])
    n_fixed = sum(1 for r in results if r["fixed"])

    lines = [
        f"Run identifier : {run_label}",
        f"Date / time    : {run_dt.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Model          : {args.model}",
        f"Total cases    : {total}",
        "",
        "Results",
        "-------",
        f"Patch built (compile proxy) : {n_patch:>3} / {total}  ({n_patch/total*100:.1f}%)",
        f"Bug fixed (tests pass)      : {n_fixed:>3} / {total}  ({n_fixed/total*100:.1f}%)",
        "",
        "Per-case breakdown",
        "------------------",
    ]
    for r in results:
        if r["fixed"]:
            status = "FIXED"
        elif r["patch_built"]:
            status = f"patch_ok / fix_failed (rc={r['return_code']})"
        else:
            status = f"patch_failed: {r['error'][:80]}"
        lines.append(f"  {r['bug_id']:<65} {status}")

    summary = "\n".join(lines)

    print("\n" + "=" * 60)
    print(summary)

    with open(out_file, "w") as f:
        f.write(summary + "\n")

    print(f"\nSummary written to {out_file}")


if __name__ == "__main__":
    main()
