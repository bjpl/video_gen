"""
API route modules for FastAPI application.
"""
from .documents import router as documents_router
from .youtube import router as youtube_router
from .generation import router as generation_router
from .jobs import router as jobs_router
from .health import router as health_router

__all__ = [
    "documents_router",
    "youtube_router",
    "generation_router",
    "jobs_router",
    "health_router",
]
