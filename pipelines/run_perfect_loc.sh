#!/usr/bin/env bash
# run_perfect_loc.sh — run perfect-localisation pipeline across models and pass@k
#
# Usage:
#   ./run_perfect_loc.sh llama3              # pass@1 only
#   ./run_perfect_loc.sh deepseek pass5      # pass@5 only
#   ./run_perfect_loc.sh mistral all         # pass@1 and pass@5
#   ./run_perfect_loc.sh all                 # all 3 models, pass@1
#   ./run_perfect_loc.sh all all             # all 3 models x pass@1 and pass@5
#
# Optional env overrides:
#   OLLAMA_HOST=http://host:port ./run_perfect_loc.sh llama3
#   SEED=42

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE="$SCRIPT_DIR/perfect_loc_pipeline.py"

OLLAMA_HOST="${OLLAMA_HOST:-http://100.97.159.90:11434}"
SEED="${SEED:-42}"

# Single shared output dir for the whole run
RUN_DIR="${SCRIPT_DIR}/experiments/$(date '+%Y-%m-%d_%H-%M-%S')_PerfectLoc"

MODEL_ARG="${1:-}"
PASS_ARG="${2:-pass1}"

run_pass() {
    local model="$1"
    local pass="$2"   # pass1 or pass5

    if [ "$pass" = "pass5" ]; then
        CANDIDATES=5
        TEMPERATURE=0.8
    else
        CANDIDATES=1
        TEMPERATURE=0.01
    fi

    echo ""
    echo "=========================================="
    echo "Model: $model  |  $pass (candidates=$CANDIDATES, temp=$TEMPERATURE)"
    echo "=========================================="

    python3 "$PIPELINE" \
        --model        "$model" \
        --candidates   "$CANDIDATES" \
        --temperature  "$TEMPERATURE" \
        --seed         "$SEED" \
        --ollama-host  "$OLLAMA_HOST" \
        --run-dir      "$RUN_DIR"
}

run_model() {
    local model="$1"
    local pass="${2:-pass1}"

    case "$pass" in
        pass1) run_pass "$model" "pass1" ;;
        pass5) run_pass "$model" "pass5" ;;
        all)
            run_pass "$model" "pass1"
            run_pass "$model" "pass5"
            ;;
        *)
            echo "Unknown pass argument: $pass (use pass1, pass5, or all)"
            exit 1
            ;;
    esac
}

case "$MODEL_ARG" in
    llama3)
        run_model "llama3:8b" "$PASS_ARG"
        ;;
    deepseek)
        run_model "deepseek-coder:6.7b" "$PASS_ARG"
        ;;
    mistral)
        run_model "mistral" "$PASS_ARG"
        ;;
    all)
        run_model "llama3:8b"          "$PASS_ARG"
        run_model "deepseek-coder:6.7b" "$PASS_ARG"
        run_model "mistral"            "$PASS_ARG"
        ;;
    *)
        echo "Usage: $0 {llama3|deepseek|mistral|all} [pass1|pass5|all]"
        echo ""
        echo "  First arg  — model selection"
        echo "    llama3    — llama3:8b"
        echo "    deepseek  — deepseek-coder:6.7b"
        echo "    mistral   — mistral"
        echo "    all       — run all three models"
        echo ""
        echo "  Second arg — pass@k selection (default: pass1)"
        echo "    pass1     — 1 candidate,  temperature=0.01"
        echo "    pass5     — 5 candidates, temperature=0.8"
        echo "    all       — both pass@1 and pass@5"
        echo ""
        echo "Optional env overrides:"
        echo "  OLLAMA_HOST=http://host:port  (default: http://100.97.159.90:11434)"
        echo "  SEED=42                       (default: 42)"
        exit 1
        ;;
esac

echo ""
echo "All results saved to: $RUN_DIR"
