#!/usr/bin/env python
"""
Simple script: Generate Internet Guide videos with AI narration
Uses the CLI tool with --use-ai flag for guaranteed AI narration
"""

import subprocess
import sys
from pathlib import Path

# Configuration
SOURCE_DOC = Path(__file__).parent.parent / "inputs" / "Internet_Guide_Vol1_Core_Infrastructure.md"
LANGUAGES = ["en", "es"]
VOICES = ["male", "female", "male_warm"]

print("🎬 Internet Guide Video Generator (AI Narration)")
print("=" * 60)
print(f"📄 Source: {SOURCE_DOC.name}")
print(f"🌍 Languages: {', '.join(LANGUAGES)}")
print(f"🎙️  Voices: {', '.join(VOICES)}")
print("✨ AI Narration: ENABLED")
print("=" * 60)

# Step 1: Generate English version with AI
print("\n📝 Generating English version with AI narration...")
result = subprocess.run([
    sys.executable,
    "scripts/create_video.py",
    "--document", str(SOURCE_DOC),
    "--use-ai",  # ✨ This enables AI narration!
    "--accent-color", "blue",
    "--auto"  # Skip prompts
], capture_output=True, text=True)

print(result.stdout)
if result.returncode != 0:
    print(f"❌ Error: {result.stderr}")
    sys.exit(1)

print("\n✅ English videos created with AI narration!")
print("\n📂 Check output/ directory for your videos")
print("\nNote: For Spanish translation, you'll need to:")
print("1. Use the multilingual builder separately")
print("2. Or manually translate and regenerate")
