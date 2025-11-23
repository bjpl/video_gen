#!/bin/bash
# Auto-Orchestrator Usage Examples
# =================================

echo "============================================="
echo "Auto-Orchestrator Examples"
echo "============================================="
echo ""

# Change to scripts directory
cd ../scripts

# Example 1: Simple document to video
echo "Example 1: Generate video from README"
echo "Command: python create_video_auto.py --from ../README.md --type document"
echo ""

# Example 2: YouTube with custom options
echo "Example 2: YouTube video with custom voice and color"
echo "Command: python create_video_auto.py --from 'python async tutorial' --type youtube --voice female --color purple"
echo ""

# Example 3: Interactive wizard
echo "Example 3: Interactive wizard mode"
echo "Command: python create_video_auto.py --type wizard"
echo ""

# Example 4: YAML with AI narration
echo "Example 4: YAML with AI-enhanced narration"
echo "Command: python create_video_auto.py --from ../inputs/demo.yaml --type yaml --use-ai"
echo ""

# Example 5: Custom duration and output
echo "Example 5: Custom duration and output directory"
echo "Command: python create_video_auto.py --from ../docs/GUIDE.md --type document --duration 120 --output-dir ../custom_output"
echo ""

echo "============================================="
echo "To run any example, copy the command above"
echo "============================================="
