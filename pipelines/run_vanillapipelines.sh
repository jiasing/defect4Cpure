#!/usr/bin/env bash
# run_pipelines.sh — launch the unified pipeline for a specific model preset
#
# Usage:
#   ./run_pipelines.sh llama3       # LLaMA 3 8B
#   ./run_pipelines.sh deepseek     # DeepSeek Coder 6.7B
#   ./run_pipelines.sh mistral      # Mistral
#   ./run_pipelines.sh vanilla      # Pure-vanilla DeepSeek Coder (distinct label)
#   ./run_pipelines.sh all          # Run all four sequentially
#
# Optional env overrides (applied before calling this script):
#   OLLAMA_HOST=http://host:port ./run_pipelines.sh llama3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE="$SCRIPT_DIR/pipeline.py"

run_model() {
    local model="$1"
    local label="$2"
    echo "=========================================="
    echo "Starting: $label  (model: $model)"
    echo "=========================================="
    python3 "$PIPELINE" --model "$model" --run-label "$label"
}

case "${1:-}" in
    llama3)
        run_model "llama3:8b" "llama3_pipeline"
        ;;
    deepseek)
        run_model "deepseek-coder:6.7b" "deepseekCoder_pipeline"
        ;;
    mistral)
        run_model "mistral" "mistral_pipeline"
        ;;
    all)
        run_model "llama3:8b"           "llama3_pipeline"
        run_model "deepseek-coder:6.7b" "deepseekCoder_pipeline"
        run_model "mistral"             "mistral_pipeline"
        ;;
    *)
        echo "Usage: $0 {llama3|deepseek|mistral|vanilla|all}"
        echo ""
        echo "  llama3    — llama3:8b             (label: llama3_pipeline)"
        echo "  deepseek  — deepseek-coder:6.7b   (label: deepseekCoder_pipeline)"
        echo "  mistral   — mistral               (label: mistral_pipeline)"
        echo "  vanilla   — deepseek-coder:6.7b   (label: pureVanilla_pipeline)"
        echo "  all       — run all four sequentially"
        echo ""
        echo "You can also call pipeline.py directly for custom models:"
        echo "  python3 pipeline.py --model <model> [--run-label <label>] [--ollama-host <url>]"
        exit 1
        ;;
esac
