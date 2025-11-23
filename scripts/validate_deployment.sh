#!/bin/bash
#
# Auto-Orchestrator Deployment Validation Script
# ==================================================
# Validates that the auto-orchestrator is properly deployed and functional
#
# Usage: bash scripts/validate_deployment.sh
#

set -e  # Exit on first error

echo "============================================================"
echo "   AUTO-ORCHESTRATOR DEPLOYMENT VALIDATION"
echo "============================================================"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0

# Test function
run_test() {
    local test_name="$1"
    local command="$2"

    echo -n "[TEST] $test_name... "

    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASS_COUNT++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((FAIL_COUNT++))
        return 1
    fi
}

echo "[1/5] Checking Python environment..."
echo "─────────────────────────────────────"
run_test "Python 3.8+ installed" "python --version | grep -E 'Python 3\.(8|9|10|11|12)'"
run_test "pip available" "pip --version"
echo ""

echo "[2/5] Checking dependencies..."
echo "─────────────────────────────────────"
run_test "PyYAML installed" "python -c 'import yaml'"
run_test "edge-tts installed" "python -c 'import edge_tts'"
run_test "Pillow installed" "python -c 'import PIL'"
run_test "numpy installed" "python -c 'import numpy'"
run_test "imageio-ffmpeg installed" "python -c 'import imageio_ffmpeg'"
echo ""

echo "[3/5] Checking scripts..."
echo "─────────────────────────────────────"
run_test "Auto-orchestrator exists" "test -f scripts/create_video_auto.py"
run_test "Document parser exists" "test -f scripts/generate_script_from_document.py"
run_test "YAML processor exists" "test -f scripts/generate_script_from_yaml.py"
run_test "Wizard exists" "test -f scripts/generate_script_wizard.py"
run_test "Unified system exists" "test -f scripts/unified_video_system.py"
echo ""

echo "[4/5] Checking auto-orchestrator..."
echo "─────────────────────────────────────"
run_test "Python syntax valid" "python -m py_compile scripts/create_video_auto.py"
run_test "Help command works" "python scripts/create_video_auto.py --help | grep -q 'Auto-orchestrator'"
run_test "CLI arguments work" "python scripts/create_video_auto.py --type document 2>&1 | grep -q 'from'"
echo ""

echo "[5/5] Running test suite..."
echo "─────────────────────────────────────"
run_test "All integration tests pass" "pytest tests/test_auto_orchestrator.py -q"
echo ""

echo "============================================================"
echo "   VALIDATION SUMMARY"
echo "============================================================"
echo ""

TOTAL_TESTS=$((PASS_COUNT + FAIL_COUNT))
echo "Total tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}✓ DEPLOYMENT VALIDATED - ALL TESTS PASSED${NC}"
    echo ""
    echo "The auto-orchestrator is ready for production use!"
    echo ""
    echo "Quick start:"
    echo "  python scripts/create_video_auto.py --from README.md --type document"
    echo ""
    exit 0
else
    echo -e "${RED}✗ DEPLOYMENT VALIDATION FAILED${NC}"
    echo ""
    echo "Please fix the failures above before deploying."
    echo "See docs/DEPLOYMENT_GUIDE.md for troubleshooting."
    echo ""
    exit 1
fi
