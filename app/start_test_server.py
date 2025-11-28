#!/usr/bin/env python3
"""Quick test server startup script"""

import uvicorn
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.dirname(__file__))

from main import app

if __name__ == "__main__":
    print("Starting Video Generation Web UI on port 8081...")
    print("Visit: http://localhost:8081")

    try:
        uvicorn.run(
            app,
            host="127.0.0.1",  # Only localhost
            port=8081,  # Different port to avoid conflicts
            log_level="info",
            access_log=True
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")