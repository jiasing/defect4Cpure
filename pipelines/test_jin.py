"""
test_jin.py — print the raw JIN API response for one test case.
No LLM call, no patching, no file output.
"""

import json
import os
import re
import requests
from pathlib import Path

DEFECTS4C_BASE_URL = "http://127.0.0.1:11111"
JIN_HOST           = "http://100.78.242.59:8000"

CVE_DATA_DIR   = Path("../defectsc_tpl/data/buggy_errmsg_cve")
CVE_DATA_FILES = [
    "single_function_repair.json",
    "single_function_single_hunk_repair.json",
    "single_function_single_line_repair.json",
]

def load_cve_data():
    shas = set()
    cve_entries = {}
    for fname in CVE_DATA_FILES:
        data = json.load(open(CVE_DATA_DIR / fname))
        for key, entry in data.items():
            sha = key.split("___")[0]
            shas.add(sha)
            cve_entries.setdefault(sha, []).append((key, entry))
    return shas, cve_entries

def get_vulnerable_code(sha, cve_entries, src_files):
    entries = cve_entries.get(sha, [])
    if not entries:
        return None
    if src_files:
        src_basenames = [os.path.basename(f) for f in src_files]
        matched = [(k, v) for k, v in entries if any(b in k for b in src_basenames)]
        if matched:
            return matched[0][1].get("buggy")
    return entries[0][1].get("buggy")


cve_shas, cve_entries = load_cve_data()
all_ids = requests.get(f"{DEFECTS4C_BASE_URL}/list_defects_bugid").json()["defects"]
cve_ids = [b for b in all_ids if b.split("@")[-1] in cve_shas]

# Use the first CVE case (deterministic)
bug_id = cve_ids[0]
sha    = bug_id.split("@")[-1]
print(f"Bug ID : {bug_id}")
print(f"SHA    : {sha}")

# Fetch defect to get source file list
defect_data = requests.get(f"{DEFECTS4C_BASE_URL}/get_defect/{bug_id}").json()
assert defect_data.get("status") == "success", f"get_defect failed: {defect_data}"

src_files = (defect_data.get("additional_info", {})
                         .get("metadata", {})
                         .get("files", {})
                         .get("src", []))

vulnerable_code = get_vulnerable_code(sha, cve_entries, src_files)

if vulnerable_code is None:
    # Fallback: pull from prompt user message
    base_prompts = defect_data["prompt_data"]["prompt"]
    user_content = next(m["content"] for m in base_prompts if m["role"] == "user")
    code_match   = re.search(r"```(?:cpp|c)?\n(.*?)\n```", user_content, re.DOTALL)
    vulnerable_code = code_match.group(1) if code_match else user_content

print(f"\n--- Vulnerable code sent to JIN ({len(vulnerable_code)} chars) ---")
print(vulnerable_code)

print("\n--- Calling JIN API ---")
resp = requests.post(
    f"{JIN_HOST}/inference/",
    headers={"Content-Type": "application/json"},
    json={"code": vulnerable_code},
    timeout=120,
)
print(f"HTTP status : {resp.status_code}")

jin_data = resp.json()
print("\n--- JIN raw response ---")
print(json.dumps(jin_data, indent=2))

out = {
    "bug_id":          bug_id,
    "sha":             sha,
    "vulnerable_code": vulnerable_code,
    "jin_response":    jin_data,
}
out_file = "test_jin_output.json"
with open(out_file, "w") as f:
    json.dump(out, f, indent=2)
print(f"\nSaved to {out_file}")
