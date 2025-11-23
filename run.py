#!/usr/bin/env python3
"""
Development Server Launcher
============================
Starts the FastAPI development server with auto-reload

Usage:
    python run.py
    python run.py --port 8080
    python run.py --host 0.0.0.0 --port 8000
"""

import sys
import argparse
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent / "app"))


def main():
    parser = argparse.ArgumentParser(
        description='Start the Video Generation System development server'
    )

    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port to bind to (default: 8000)'
    )

    parser.add_argument(
        '--reload',
        action='store_true',
        default=True,
        help='Enable auto-reload (default: True)'
    )

    parser.add_argument(
        '--no-reload',
        dest='reload',
        action='store_false',
        help='Disable auto-reload'
    )

    args = parser.parse_args()

    print("\n" + "="*80)
    print("🎬 Video Generation System - Development Server")
    print("="*80)
    print(f"\n📡 Server: http://{args.host}:{args.port}")
    print(f"🔄 Auto-reload: {'Enabled' if args.reload else 'Disabled'}")
    print("\n💡 Features:")
    print("   • HTMX + Alpine.js frontend")
    print("   • FastAPI async backend")
    print("   • Real-time SSE progress updates")
    print("   • Integration with video generation scripts")
    print("\n⌨️  Press Ctrl+C to stop the server")
    print("="*80 + "\n")

    # Import and run uvicorn
    import uvicorn

    try:
        uvicorn.run(
            "main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            reload_dirs=["app"] if args.reload else None
        )
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped. Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
