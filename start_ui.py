#!/usr/bin/env python
"""
Quick start script for Video Generation Web UI
Automatically finds available port and starts server
"""
import socket
import uvicorn
import sys
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from main import app

def find_available_port(start_port=8000, max_attempts=10):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No available ports found between {start_port} and {start_port + max_attempts}")

if __name__ == "__main__":
    port = find_available_port()

    print("=" * 60)
    print("🎬 Video Generation Web UI")
    print("=" * 60)
    print(f"\n✅ Server starting on port {port}")
    print(f"\n🌐 Open in browser: http://localhost:{port}")
    print("\n📚 Features:")
    print("   • 4 input methods: Manual, Document, YouTube, YAML")
    print("   • Multilingual: 28+ languages")
    print("   • Advanced scene builder")
    print("   • Real-time progress tracking")
    print("\n" + "=" * 60)
    print("\nPress Ctrl+C to stop the server\n")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True
    )
