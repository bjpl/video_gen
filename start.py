#!/usr/bin/env python3
"""
Production startup script for video_gen.
Handles environment setup and provides better error reporting.
"""
import os
import sys
from pathlib import Path

def main():
    # Print startup info
    print("=" * 60)
    print("VIDEO_GEN STARTUP")
    print("=" * 60)

    # Get port from environment (Railway provides PORT)
    port_raw = os.environ.get("PORT", "8000")

    # Handle case where PORT might be set to literal "$PORT" string
    if port_raw == "$PORT" or not port_raw.isdigit():
        print(f"WARNING: Invalid PORT value '{port_raw}', defaulting to 8000")
        port = "8000"
    else:
        port = port_raw

    host = os.environ.get("HOST", "0.0.0.0")

    print(f"PORT: {port}")
    print(f"HOST: {host}")
    print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'not set')}")
    print(f"Working directory: {os.getcwd()}")
    print(f"Python: {sys.executable}")
    print(f"Python version: {sys.version}")

    # Ensure we're in the right directory
    app_root = Path(__file__).parent
    os.chdir(app_root)
    print(f"Changed to: {os.getcwd()}")

    # Add paths for imports
    sys.path.insert(0, str(app_root))
    sys.path.insert(0, str(app_root / "scripts"))

    # Check required directories exist
    required_dirs = ["app", "video_gen", "scripts"]
    for d in required_dirs:
        path = app_root / d
        exists = path.exists()
        print(f"  {d}/: {'OK' if exists else 'MISSING'}")
        if not exists:
            print(f"ERROR: Required directory {d} is missing!")
            sys.exit(1)

    # Test critical imports
    print("\nTesting imports...")
    try:
        print("  - fastapi...", end=" ")
        import fastapi
        print("OK")

        print("  - uvicorn...", end=" ")
        import uvicorn
        print("OK")

        print("  - video_gen.pipeline...", end=" ")
        from video_gen.pipeline import get_pipeline
        print("OK")

        print("  - language_config...", end=" ")
        from language_config import MULTILINGUAL_VOICES
        print("OK")

        print("  - app.main...", end=" ")
        from app.main import app
        print("OK")

    except ImportError as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 60)
    print(f"Starting server on {host}:{port}")
    print("=" * 60 + "\n")

    # Start uvicorn
    uvicorn.run(
        "app.main:app",
        host=host,
        port=int(port),
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    main()
