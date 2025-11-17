"""
Railway entry point - imports the FastAPI app from app.main
"""
from app.main import app

if __name__ == "__main__":
    import uvicorn
    import os

    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
