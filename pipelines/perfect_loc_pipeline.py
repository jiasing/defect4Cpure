import argparse
import json
import re
import requests
import time
import os
from datetime import datetime
from pathlib import Path
from openai import OpenAI

# ── Constants ─────────────────────────────────────────────────────────────────
DEFECTS4C_BASE_URL = "http://127.0.0.1:11111"

CVE_DATA_DIR = Path("../defectsc_tpl/data/buggy_errmsg_cve")
CVE_DATA_FILES = [
    "single_function_repair.json",
    "single_function_single_hunk_repair.json",
    "single_function_single_line_repair.json",
]

PERFECT_LOC_FILE = Path("../defectsc_tpl/perfect_localisation.json")

BASE_SYSTEM_PROMPT = "You are a C/CPP code program repair expert"
INFILL_SPLIT = ">>> [ INFILL ] <<<"


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_cve_data() -> tuple:
    shas = set()
    cve_entries = {}
    for fname in CVE_DATA_FILES:
        data = json.load(open(CVE_DATA_DIR / fname))
        for key, entry in data.items():
            sha = key.split("___")[0]
            shas.add(sha)
            cve_entries.setdefault(sha, []).append((key, entry))
    return shas, cve_entries


def load_perfect_localisation() -> dict:
    """Returns dict keyed by bug_id -> localisation entry."""
    entries = json.load(open(PERFECT_LOC_FILE))
    return {e["bug_id"]: e for e in entries}


def get_vulnerable_code(sha: str, cve_entries: dict, src_files: list) -> str:
    entries = cve_entries.get(sha, [])
    if not entries:
        return None
    if src_files:
        src_basenames = [os.path.basename(f) for f in src_files]
        matched = [(k, v) for k, v in entries if any(b in k for b in src_basenames)]
        if matched:
            return matched[0][1].get("buggy")
    return entries[0][1].get("buggy")


def patch_user_message(user_content: str, vulnerable_code: str) -> str:
    patched = re.sub(
        r"```(?:cpp|c)?\n.*?" + re.escape(INFILL_SPLIT) + r".*?```",
        f"```c\n{vulnerable_code}\n```",
        user_content,
        flags=re.DOTALL,
    )
    patched = re.sub(r"\bbuggy\b", "vulnerable", patched, flags=re.IGNORECASE)
    for _variant in [
        "The following code contains a vulnerable line that has been removed.",
        "The following code contains a vulnerable hunk that has been removed.",
        "The following code contains a vulnerable function that has been removed.",
    ]:
        patched = patched.replace(_variant, "The following code contains a vulnerable function. Fix the vulnerability.")
    return patched


def format_perfect_loc(entry: dict) -> str:
    """Format perfect localisation entry to match JIN localisation signal format."""
    lines = entry.get("changed_lines", [])

    loc_lines = "\n".join(
        f"- line {l['line_in_func']}: score=1.0000 | {l['content']}" for l in lines
    )

    return (
        f"Fault localisation: Localisation signals:\n"
        f"- threshold: 1.00\n"
        f"- Ground truth localisation — exact vulnerable lines (oracle).\n"
        f"- Lines at or above threshold:\n"
        f"{loc_lines}"
    )


def build_messages(base_prompts: list, loc_text: str) -> tuple:
    """Returns (messages, system_msg, user_msg)."""
    system_msg = BASE_SYSTEM_PROMPT + "\n\n" + loc_text

    user_msg = next(m["content"] for m in base_prompts if m["role"] == "user")

    messages = [{"role": "system", "content": system_msg}]
    for m in base_prompts:
        if m["role"] == "system":
            continue
        elif m["role"] == "user":
            messages.append({"role": "user", "content": user_msg})
        else:
            messages.append(m)

    return messages, system_msg, user_msg


def extract_code(llm_response: str) -> str:
    match = re.search(r"```(?:cpp|c)?\n(.*?)\n```", llm_response, re.DOTALL)
    if match:
        return match.group(1).strip()
    return llm_response.strip()


def format_patch_block(idx: int, total: int, bug_id: str, loc_entry: dict,
                       system_msg: str, user_msg: str,
                       patch: str, compile_result: bool, fix_result: bool) -> str:
    sha = bug_id.split("@")[-1]
    lines_info = loc_entry.get("changed_lines", []) if loc_entry else []
    category   = loc_entry.get("category", "N/A")  if loc_entry else "N/A"

    lines = [
        f"{'='*60}",
        f"[{idx}/{total}] {bug_id}",
        f"SHA: {sha}",
        "Perfect localisation:",
        f"  category : {category}",
    ]
    for l in lines_info:
        lines.append(f"  line {l['line_in_func']:>4}: {l['content']}")

    lines += [
        "",
        "Prompt sent to LLM:",
        f"  [system] {system_msg}",
        f"  [user]   {user_msg[:300]}{'...' if len(user_msg) > 300 else ''}",
        "",
        "Extracted patch:",
        patch if patch else "(none)",
        "",
        f"Compile : {compile_result}",
        f"Fixed   : {fix_result}",
    ]
    return "\n".join(lines)


# ── Core pipeline ─────────────────────────────────────────────────────────────

def process_defect(bug_id: str, client: OpenAI, model: str,
                   temperature: float, seed: int, candidates: int,
                   cve_entries: dict, perfect_loc: dict) -> dict:
    result = {
        "bug_id":          bug_id,
        "patch_built":     False,
        "fixed":           False,
        "return_code":     None,
        "error":           "",
        "loc_entry":       {},
        "system_msg":      "",
        "user_msg":        "",
        "extracted_patch": "",
    }

    # Step 1: Fetch defect
    response = requests.get(f"{DEFECTS4C_BASE_URL}/get_defect/{bug_id}")
    defect_data = response.json()
    if defect_data.get("status") != "success":
        result["error"] = f"get_defect failed: {defect_data}"
        return result

    base_prompts = defect_data["prompt_data"]["prompt"]

    # Step 1b: Patch prompt with actual vulnerable code
    sha = bug_id.split("@")[-1]
    src_files = (defect_data.get("additional_info", {})
                             .get("metadata", {})
                             .get("files", {})
                             .get("src", []))
    vulnerable_code = get_vulnerable_code(sha, cve_entries, src_files)

    if vulnerable_code is not None:
        base_prompts = [
            {**m, "content": patch_user_message(m["content"], vulnerable_code)}
            if m["role"] == "user" else m
            for m in base_prompts
        ]

    # Step 2: Look up perfect localisation for this bug
    loc_entry = perfect_loc.get(bug_id)
    result["loc_entry"] = loc_entry or {}

    if loc_entry:
        loc_text = format_perfect_loc(loc_entry)
    else:
        # No perfect loc available — fall back to base prompt only
        loc_text = ""
        result["error"] = "no perfect localisation entry found for this bug_id"

    # Step 3: Build messages
    messages, system_msg, user_msg = build_messages(base_prompts, loc_text)
    result["system_msg"] = system_msg
    result["user_msg"]   = user_msg

    # Step 4: Generate candidates and try each
    for attempt in range(candidates):
        try:
            ai_response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=4096,
                seed=seed + attempt,
            )
            llm_response = ai_response.choices[0].message.content
        except Exception as e:
            result["error"] = f"LLM error: {e}"
            continue

        extracted = extract_code(llm_response)
        result["extracted_patch"] = extracted

        # Step 5: Build patch
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
            continue

        result["patch_built"] = True
        patch_path = patch_data["fix_p"]

        # Step 6: Submit fix
        fix_response = requests.post(
            f"{DEFECTS4C_BASE_URL}/fix",
            headers={"Content-Type": "application/json"},
            json={"bug_id": bug_id, "patch_path": patch_path},
        )
        fix_data = fix_response.json()
        if "handle" not in fix_data:
            result["error"] = f"fix submission failed: {fix_data}"
            continue

        handle = fix_data["handle"]

        # Step 7: Poll for result
        start_time = time.time()
        while time.time() - start_time < 300:
            status_data = requests.get(f"{DEFECTS4C_BASE_URL}/status/{handle}").json()
            current = status_data.get("status", "unknown")
            if current in ("completed", "failed"):
                rc = status_data.get("return_code", -1)
                result["return_code"] = rc
                if rc == 0:
                    result["fixed"] = True
                    return result
                else:
                    result["error"] = status_data.get("error", "")[:200]
                break
            time.sleep(10)

    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Defects4C perfect-localisation pipeline")
    parser.add_argument("--model",       required=True,
                        help="Model name (e.g. llama3:8b)")
    parser.add_argument("--candidates",  type=int, default=1,
                        help="Number of patch candidates per bug (Pass@k)")
    parser.add_argument("--seed",        type=int, default=42)
    parser.add_argument("--temperature", type=float, default=0.01,
                        help="LLM sampling temperature (use ~0.8 for pass@k, ~0.0 for pass@1)")
    parser.add_argument("--ollama-host", default=os.getenv("OLLAMA_HOST", "http://100.97.159.90:11434"))
    parser.add_argument("--run-dir",     default=None,
                        help="Output directory (default: pipelines/experiments/<datetime>)")
    args = parser.parse_args()

    run_dt     = datetime.now()
    model_slug = args.model.replace(":", "-").replace("/", "-")

    if args.run_dir:
        out_dir = Path(args.run_dir)
    else:
        out_dir = Path(__file__).parent / "experiments" / run_dt.strftime("%Y-%m-%d_%H-%M-%S")
    out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / f"{model_slug}_PerfectLoc.txt"

    client = OpenAI(
        api_key="ollama",
        base_url=f"{args.ollama_host}/v1/",
    )

    cve_shas, cve_entries = load_cve_data()
    perfect_loc           = load_perfect_localisation()

    all_ids = requests.get(f"{DEFECTS4C_BASE_URL}/list_defects_bugid").json()["defects"]
    cve_ids = [b for b in all_ids if b.split("@")[-1] in cve_shas]
    total   = len(cve_ids)

    setup_lines = [
        "PERFECT LOCALISATION PIPELINE RUN",
        "=" * 60,
        f"Timestamp       : {run_dt.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Model           : {args.model}",
        f"Augmentation    : perfect localisation (ground truth)",
        f"Candidates (k)  : {args.candidates}",
        f"Temperature     : {args.temperature}",
        f"Seed            : {args.seed}",
        f"Ollama host     : {args.ollama_host}",
        f"Base system prompt: {BASE_SYSTEM_PROMPT}",
        f"Total CVE cases : {total}",
        "=" * 60,
        "",
    ]
    header = "\n".join(setup_lines)
    print(header)

    results    = []
    patch_logs = []

    for i, bug_id in enumerate(cve_ids, 1):
        print(f"[{i}/{total}] {bug_id}")
        result = process_defect(
            bug_id      = bug_id,
            client      = client,
            model       = args.model,
            temperature = args.temperature,
            seed        = args.seed,
            candidates  = args.candidates,
            cve_entries = cve_entries,
            perfect_loc = perfect_loc,
        )
        results.append(result)

        if result["fixed"]:
            print("  FIXED")
        elif result["patch_built"]:
            print(f"  patch built, fix failed (rc={result['return_code']})")
        else:
            print(f"  patch failed: {result['error'][:100]}")

        patch_logs.append(format_patch_block(
            idx            = i,
            total          = total,
            bug_id         = bug_id,
            loc_entry      = result["loc_entry"],
            system_msg     = result["system_msg"],
            user_msg       = result["user_msg"],
            patch          = result["extracted_patch"],
            compile_result = result["patch_built"],
            fix_result     = result["fixed"],
        ))

    n_compile = sum(1 for r in results if r["patch_built"])
    n_fixed   = sum(1 for r in results if r["fixed"])

    summary_lines = [
        "",
        "=" * 60,
        "OVERALL RESULTS",
        "=" * 60,
        f"Total cases   : {total}",
        f"Compile Rate  : {n_compile:>3} / {total}  ({n_compile/total*100:.1f}%)",
        f"Pass@{args.candidates:<2}        : {n_fixed:>3} / {total}  ({n_fixed/total*100:.1f}%)",
    ]
    summary = "\n".join(summary_lines)
    print(summary)

    with open(out_file, "w") as f:
        f.write(header)
        f.write("\n".join(patch_logs))
        f.write(summary + "\n")

    print(f"\nResults saved to {out_file}")


if __name__ == "__main__":
    main()
