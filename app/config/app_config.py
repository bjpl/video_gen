"""
Application-level configuration for the FastAPI backend.

This module contains path configuration and template setup.
"""
from pathlib import Path
from fastapi.templating import Jinja2Templates


# Base directory for the application
BASE_DIR = Path(__file__).parent.parent


def get_templates() -> Jinja2Templates:
    """
    Initialize and return Jinja2 templates with auto-reload enabled.

    Returns:
        Configured Jinja2Templates instance
    """
    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    templates.env.auto_reload = True  # Force template reloading in production
    return templates


def get_static_dir() -> Path:
    """
    Get path to static files directory.

    Returns:
        Path to static files
    """
    return BASE_DIR / "static"


def get_uploads_dir() -> Path:
    """
    Get path to uploads directory, creating it if necessary.

    Returns:
        Path to uploads directory
    """
    uploads_dir = BASE_DIR.parent / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    return uploads_dir
