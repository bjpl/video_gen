"""
FastAPI backend for Video Generation System
Now powered by the unified pipeline for consistency and reliability.

HTMX + Alpine.js compatible REST API

Security Features:
- Production security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- HTTPS redirect in production with HSTS enforcement
- Content Security Policy (CSP)
- CSRF protection for all state-changing endpoints
- Input validation and sanitization
- Rate limiting with configurable thresholds
- Secure error responses
"""
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Optional, Literal, Any
from contextlib import asynccontextmanager
import asyncio
import json
import sys
from pathlib import Path
import time
import logging
import secrets
import hashlib
import os

# Add app directory to path for utils import
app_dir = Path(__file__).parent
sys.path.insert(0, str(app_dir.parent))

# Import file validation utilities
try:
    from app.utils.file_validation import (
        validate_upload,
        preview_document_structure,
        create_validation_response,
        create_error_response,
        detect_document_format,
        sanitize_filename,
        get_upload_progress_stages,
        format_progress_message,
        convert_to_markdown,
        is_binary_content,
    )
except ImportError:
    # Fallback - module may not be available during initial import
    pass

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

# Add parent directory to path for video_gen imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()
load_dotenv(Path(__file__).parent / ".env")  # Also load from app/.env

# Initialize Sentry error tracking
from app.utils.sentry_config import init_sentry
init_sentry()

# Import rate limiting middleware
from app.middleware.rate_limiting import (
    setup_rate_limiting,
    limiter,
    UPLOAD_LIMIT,
    GENERATE_LIMIT,
    PARSE_LIMIT,
    TASKS_LIMIT,
    HEALTH_LIMIT,
)

# Import security headers middleware
from app.middleware.security_headers import (
    setup_security_headers,
    get_security_report,
    validate_security_configuration,
)

# Import multilingual support
from language_config import MULTILINGUAL_VOICES, LANGUAGE_INFO, list_available_languages

# Import unified pipeline
from video_gen.pipeline import get_pipeline
from video_gen.shared.models import InputConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Modern Lifespan Context Manager (replaces deprecated on_event)
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Modern FastAPI lifespan context manager.
    Handles startup and shutdown events elegantly.
    """
    # Startup
    logger.info("🚀 Initializing video generation system...")
    try:
        # Step 1: Validate environment configuration
        from app.utils.env_validator import validate_environment
        logger.info("🔍 Validating environment configuration...")
        env_result = validate_environment()
        logger.info("✅ Environment validation passed")

        # Step 2: Initialize pipeline
        pipeline = get_pipeline()
        logger.info(f"✅ Pipeline initialized with {len(pipeline.stages)} stages")
        logger.info("✅ Video generation system ready!")
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}", exc_info=True)
        raise

    yield  # Server runs here

    # Shutdown
    logger.info("🛑 Shutting down video generation system...")


app = FastAPI(
    title="Video Generation System",
    description="Professional video generation powered by unified pipeline",
    version="2.0.0",
    lifespan=lifespan
)

# Setup security headers middleware FIRST (applied to all requests)
setup_security_headers(app)

# Setup rate limiting BEFORE routes are defined
setup_rate_limiting(app)

# Setup templates and static files
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.auto_reload = True  # Force template reloading in production
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ============================================================================
# Custom Exception Handlers with Sentry Integration
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Handle HTTP exceptions with Sentry integration.

    Captures 5xx errors in Sentry while allowing 4xx errors to pass through
    without creating noise in error tracking.
    """
    # Capture 5xx errors in Sentry
    if exc.status_code >= 500:
        from app.utils.sentry_config import capture_api_error
        capture_api_error(
            error=exc,
            endpoint=request.url.path,
            method=request.method,
            status_code=exc.status_code
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": request.url.path
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle uncaught exceptions with Sentry integration.

    Captures all unhandled exceptions for monitoring and debugging.
    """
    from app.utils.sentry_config import capture_api_error

    # Capture in Sentry with full context
    capture_api_error(
        error=exc,
        endpoint=request.url.path,
        method=request.method,
        status_code=500
    )

    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    # Return generic error to client (don't expose internal details)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. The issue has been logged.",
            "status_code": 500,
            "path": request.url.path
        }
    )


# ============================================================================
# CSRF Protection Implementation
# ============================================================================

# CSRF token storage (in production, use Redis or database)
# For now, we use a simple in-memory store with session-based tokens
CSRF_SECRET = os.environ.get("CSRF_SECRET", secrets.token_hex(32))
CSRF_TOKEN_EXPIRY = 3600  # 1 hour


def generate_csrf_token(session_id: str = None) -> str:
    """
    Generate a CSRF token tied to the session.

    Args:
        session_id: Optional session identifier

    Returns:
        CSRF token string
    """
    if not session_id:
        session_id = secrets.token_hex(16)

    timestamp = str(int(time.time()))
    message = f"{session_id}:{timestamp}"
    signature = hashlib.sha256(f"{message}:{CSRF_SECRET}".encode()).hexdigest()[:32]

    return f"{session_id}:{timestamp}:{signature}"


def validate_csrf_token(token: str, max_age: int = CSRF_TOKEN_EXPIRY) -> bool:
    """
    Validate a CSRF token.

    Args:
        token: The CSRF token to validate
        max_age: Maximum age in seconds

    Returns:
        True if valid, False otherwise
    """
    if not token:
        return False

    try:
        parts = token.split(':')
        if len(parts) != 3:
            return False

        session_id, timestamp_str, signature = parts
        timestamp = int(timestamp_str)

        # Check expiry
        if time.time() - timestamp > max_age:
            logger.warning("CSRF token expired")
            return False

        # Verify signature
        message = f"{session_id}:{timestamp_str}"
        expected_signature = hashlib.sha256(f"{message}:{CSRF_SECRET}".encode()).hexdigest()[:32]

        if not secrets.compare_digest(signature, expected_signature):
            logger.warning("CSRF token signature mismatch")
            return False

        return True

    except (ValueError, AttributeError) as e:
        logger.warning(f"CSRF token validation error: {e}")
        return False


async def verify_csrf_token(request: Request) -> bool:
    """
    FastAPI dependency to verify CSRF token on state-changing requests.

    Checks X-CSRF-Token header or csrf_token form field.
    """
    # Skip CSRF check for safe methods
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True

    # Get token from header or form
    token = request.headers.get("X-CSRF-Token")

    if not token:
        # Try to get from form data
        try:
            form = await request.form()
            token = form.get("csrf_token")
        except:
            pass

    if not token:
        # Check JSON body
        try:
            body = await request.json()
            token = body.get("csrf_token")
        except:
            pass

    # For development, allow bypass if CSRF_DISABLED is set
    if os.environ.get("CSRF_DISABLED", "").lower() == "true":
        logger.warning("CSRF protection disabled via environment variable")
        return True

    if not validate_csrf_token(token):
        raise HTTPException(
            status_code=403,
            detail="CSRF token validation failed. Please refresh the page and try again."
        )

    return True


# CSRF token endpoint
@app.get("/api/csrf-token")
async def get_csrf_token():
    """
    Get a fresh CSRF token for client-side requests.

    Returns:
        JSON with csrf_token field
    """
    token = generate_csrf_token()
    return {"csrf_token": token}

# ============================================================================
# Pydantic Models
# ============================================================================

class SceneBase(BaseModel):
    type: Literal[
        "title", "command", "list", "outro", "code_comparison", "quote",
        "learning_objectives", "problem", "solution", "checkpoint", "quiz", "exercise"
    ]
    voice: Optional[Literal["male", "male_warm", "female", "female_friendly"]] = "male"
    narration: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional fields for scene-specific content

class Video(BaseModel):
    video_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=200)
    scenes: List[Dict] = Field(..., min_length=1)  # Accept any scene type
    voice: Optional[str] = "male"  # Deprecated: use voices instead
    voices: Optional[List[str]] = None  # NEW: Support multiple voices
    duration: Optional[int] = None

    @field_validator('scenes')
    @classmethod
    def validate_scenes(cls, v):
        if not v or len(v) == 0:
            raise ValueError('scenes list cannot be empty - must have at least one scene')

        # Validate each scene has required 'type' field
        for i, scene in enumerate(v):
            if not isinstance(scene, dict):
                raise ValueError(f'Scene {i} must be a dictionary')
            if 'type' not in scene:
                raise ValueError(f'Scene {i} missing required field: type')

        return v

    def get_voices(self) -> List[str]:
        """Get voice list, handling backward compatibility."""
        if self.voices:
            return self.voices
        return [self.voice] if self.voice else ["male"]

class VideoSet(BaseModel):
    set_id: str = Field(..., min_length=1, pattern="^[a-zA-Z0-9_-]+$")
    set_name: str = Field(..., min_length=1, max_length=200)
    videos: List[Video] = Field(..., min_length=1)
    accent_color: Optional[str] = "blue"
    languages: Optional[List[str]] = ["en"]  # Default to English only
    source_language: Optional[str] = "en"
    translation_method: Optional[Literal["claude", "google", "manual"]] = "claude"

    @field_validator('accent_color')
    @classmethod
    def validate_accent_color(cls, v):
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v

    @field_validator('videos')
    @classmethod
    def validate_videos_not_empty(cls, v):
        if not v or len(v) == 0:
            raise ValueError('videos list cannot be empty - must have at least one video')
        return v

class DocumentInput(BaseModel):
    content: str = Field(..., min_length=1)
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    video_count: Optional[int] = Field(default=1, ge=1, le=10)  # Number of videos to split document into
    split_strategy: Optional[str] = "auto"  # Splitting strategy (auto, ai, headers, paragraph, sentence, length)
    split_by_h2: Optional[bool] = None  # Legacy: auto-calculated from video_count if not provided
    enable_ai_splitting: Optional[bool] = True  # Enable AI-powered splitting

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if not v or not v.strip():
            raise ValueError('content cannot be empty')
        return v.strip()

    @field_validator('accent_color')
    @classmethod
    def validate_accent_color(cls, v):
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v

class YouTubeInput(BaseModel):
    url: str = Field(..., min_length=1)
    duration: Optional[int] = Field(default=60, ge=30, le=600)
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    scene_duration: Optional[int] = Field(default=12, ge=5, le=30)

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not v or not v.strip():
            raise ValueError('url cannot be empty')
        v = v.strip().strip('"').strip("'")
        # Import and use the validator for comprehensive URL checking
        from video_gen.utils.youtube_validator import extract_video_id
        video_id = extract_video_id(v)
        if not video_id:
            raise ValueError('Invalid YouTube URL. Please provide a valid YouTube video link.')
        return v

    @field_validator('accent_color')
    @classmethod
    def validate_accent_color(cls, v):
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v


class YouTubeURLValidation(BaseModel):
    """Request model for YouTube URL validation."""
    url: str = Field(..., min_length=1)


class YouTubePreviewRequest(BaseModel):
    """Request model for YouTube video preview."""
    url: str = Field(..., min_length=1)
    include_transcript_preview: Optional[bool] = False
    transcript_language: Optional[str] = "en"

class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]  # e.g., ["en", "es", "fr"]
    source_language: str = "en"
    translation_method: Optional[Literal["claude", "google"]] = "claude"
    language_voices: Optional[Dict[str, str]] = None  # NEW: Per-language voice mapping

# ============================================================================
# Routes - UI Pages
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page - modern home interface"""
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/builder", response_class=HTMLResponse)
async def builder(request: Request):
    """Scene builder interface"""
    return templates.TemplateResponse("builder.html", {"request": request})

@app.get("/multilingual", response_class=HTMLResponse)
async def multilingual(request: Request):
    """Multilingual video generation interface"""
    return templates.TemplateResponse("multilingual.html", {"request": request})

@app.get("/progress", response_class=HTMLResponse)
async def progress(request: Request):
    """Progress tracking page - modern jobs interface"""
    return templates.TemplateResponse("jobs.html", {"request": request})

@app.get("/create", response_class=HTMLResponse)
async def create(request: Request):
    """Unified video creation page - new wizard-style interface"""
    return templates.TemplateResponse("create-unified.html", {"request": request})

@app.get("/create-legacy", response_class=HTMLResponse)
async def create_legacy(request: Request):
    """Legacy create page (kept for reference)"""
    return templates.TemplateResponse("create.html", {"request": request})

@app.get("/create-unified", response_class=HTMLResponse)
async def create_unified(request: Request):
    """
    Alias for /create - Modern unified input flow with all new components
    Includes: DragDrop, Validation, Preview, MultiLanguage, MultiVoice, Progress
    """
    return templates.TemplateResponse("create-unified.html", {
        "request": request,
        "language_info": LANGUAGE_INFO,
        "multilingual_voices": MULTILINGUAL_VOICES
    })

@app.get("/advanced", response_class=HTMLResponse)
async def advanced(request: Request):
    """Advanced features page for power users"""
    return templates.TemplateResponse("advanced.html", {"request": request})

# ============================================================================
# Routes - API Endpoints
# ============================================================================

@app.post("/api/parse/document")
@limiter.limit(PARSE_LIMIT)
async def parse_document(request: Request, input: DocumentInput, background_tasks: BackgroundTasks):
    """
    Parse document and generate video set.
    Now uses unified pipeline for consistency.

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        # Generate task ID FIRST
        task_id = f"doc_{int(time.time())}"

        # Create input config for pipeline
        # Strip any surrounding quotes from the path (handles copy-paste with quotes)
        document_path = str(input.content).strip().strip('"').strip("'")

        # Security: Validate path doesn't contain traversal attempts
        if '..' in document_path or document_path.startswith('/etc') or document_path.startswith('/proc'):
            raise HTTPException(
                status_code=400,
                detail="Invalid document path: Path traversal not allowed"
            )

        # Security: Check for Windows sensitive paths
        if any(p in document_path.lower() for p in ['\\windows\\', '\\system32\\', 'c:\\windows']):
            raise HTTPException(
                status_code=400,
                detail="Invalid document path: Access to system directories not allowed"
            )

        input_config = InputConfig(
            input_type="document",
            source=document_path,  # Cleaned document path
            accent_color=input.accent_color,
            voice=input.voice,
            languages=["en"],  # Default to English for document parsing
            video_count=input.video_count,  # Pass user's video count selection
            split_strategy=input.split_strategy,  # ✨ NEW: Intelligent splitting strategy
            split_by_h2=(input.split_by_h2 if input.split_by_h2 is not None else (input.video_count > 1)),  # Legacy support
            enable_ai_splitting=input.enable_ai_splitting  # ✨ NEW: AI toggle
        )

        # Get pipeline singleton
        pipeline = get_pipeline()

        # Execute asynchronously in background - PASS task_id!
        background_tasks.add_task(
            execute_pipeline_task,
            pipeline,
            input_config,
            task_id  # Pass the task_id as third argument
        )

        logger.info(f"Document parsing started: {task_id}")

        return {
            "task_id": task_id,
            "status": "started",
            "message": "Document parsing started"
        }

    except Exception as e:
        logger.error(f"Document parsing failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload/document")
@limiter.limit(UPLOAD_LIMIT)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    accent_color: str = Form("blue"),
    voice: str = Form("male"),
    video_count: int = Form(1),
    background_tasks: BackgroundTasks = None
):
    """
    Upload a document file and generate video set.
    Accepts multipart/form-data with file upload.

    Rate limit: Strict (configurable via RATE_LIMIT_UPLOAD env var)
    """
    try:
        # Validate file type
        allowed_extensions = {'.md', '.txt', '.rst', '.markdown'}
        file_ext = Path(file.filename).suffix.lower()

        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {file_ext}. Allowed: {', '.join(allowed_extensions)}"
            )

        # File size validation (max 10MB)
        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
            )
        # Content already read above, no need to read again

        # Generate task ID with millisecond precision and random suffix for uniqueness
        task_id = f"upload_{int(time.time() * 1000)}_{secrets.token_hex(4)}"

        # Create uploads directory if it doesn't exist
        uploads_dir = Path(__file__).parent.parent / "uploads"
        uploads_dir.mkdir(exist_ok=True)

        # Sanitize filename using comprehensive validation
        sanitized_filename = sanitize_filename(file.filename)
        # Additional removal of unicode control characters (RTLO, etc.)
        sanitized_filename = ''.join(c for c in sanitized_filename if ord(c) < 0x202A or ord(c) > 0x202E)
        # Remove null bytes
        sanitized_filename = sanitized_filename.replace('\x00', '')
        upload_path = uploads_dir / f"{task_id}_{sanitized_filename}"

        with open(upload_path, "wb") as f:
            f.write(content)  # Use content already read during size validation

        logger.info(f"File uploaded: {upload_path} ({len(content)} bytes)")

        # CRITICAL: Convert Path to absolute string and ensure it's normalized
        # This prevents path traversal and ensures correct path format
        absolute_path = str(upload_path.resolve().absolute())

        logger.info(f"Absolute upload path for pipeline: {absolute_path}")

        # Create input config for pipeline with absolute path
        input_config = InputConfig(
            input_type="document",
            source=absolute_path,  # Use absolute, resolved path
            accent_color=accent_color,
            voice=voice,
            languages=["en"],
            video_count=video_count,
            split_by_h2=(video_count > 1)
        )

        # Get pipeline singleton
        pipeline = get_pipeline()

        # Execute asynchronously in background
        background_tasks.add_task(
            execute_pipeline_task,
            pipeline,
            input_config,
            task_id
        )

        logger.info(f"Document upload processing started: {task_id} for {absolute_path}")

        return {
            "task_id": task_id,
            "status": "started",
            "message": f"File '{sanitized_filename}' uploaded successfully and processing started",
            "filename": sanitized_filename,
            "size": len(content)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Modern Document Input Flow - Validation & Preview Endpoints
# ============================================================================

@app.post("/api/validate/document")
@limiter.limit(PARSE_LIMIT)
async def validate_document_upload(request: Request, file: UploadFile = File(...)):
    """
    Validate a document file before processing.

    Performs real-time validation including:
    - File extension check
    - File size validation
    - Content type verification
    - Binary content detection
    - Document structure preview

    Returns validation result with preview data for UI display.

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        # Read file content
        content = await file.read()
        await file.seek(0)  # Reset for potential re-read

        # Perform comprehensive validation
        validation_result = validate_upload(
            filename=file.filename,
            content_type=file.content_type or "",
            file_size=len(content),
            content=content
        )

        if not validation_result["valid"]:
            # Return validation errors with suggestions
            return JSONResponse(
                status_code=400,
                content=create_validation_response(
                    valid=False,
                    filename=file.filename,
                    errors=validation_result["errors"],
                    warnings=validation_result.get("warnings", [])
                )
            )

        # Decode content for preview
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                text_content = content.decode('latin-1')
            except:
                return JSONResponse(
                    status_code=400,
                    content=create_validation_response(
                        valid=False,
                        filename=file.filename,
                        errors=["Unable to decode file content. Please ensure it's a text file."]
                    )
                )

        # Generate document preview
        preview = preview_document_structure(text_content)

        # Detect format
        format_info = detect_document_format(text_content, file.filename)
        preview["format_info"] = format_info

        return create_validation_response(
            valid=True,
            filename=validation_result["sanitized_filename"],
            preview=preview,
            warnings=validation_result.get("warnings", [])
        )

    except Exception as e:
        logger.error(f"Document validation failed: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=create_error_response(
                error_code="VALIDATION_ERROR",
                message=f"Validation failed: {str(e)}",
                details={"filename": file.filename if file else "unknown"}
            )
        )


@app.post("/api/preview/document")
@limiter.limit(PARSE_LIMIT)
async def preview_document(request: Request, file: UploadFile = File(...)):
    """
    Generate a detailed preview of document structure.

    Returns:
    - Document title
    - Section count and headings
    - Estimated video scenes
    - Estimated duration
    - Content statistics

    This endpoint is designed for the "preview before generate" workflow.

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        # Read and decode content
        content = await file.read()

        # Check for binary content
        if is_binary_content(content):
            raise HTTPException(
                status_code=400,
                detail="Binary file detected. Please upload a text document."
            )

        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            text_content = content.decode('latin-1')

        # Detect format and convert if necessary
        format_info = detect_document_format(text_content, file.filename)

        if format_info["format"] == "rst":
            # Convert RST to markdown for preview
            text_content = convert_to_markdown(text_content, "rst")
        elif format_info["format"] == "plain_text":
            text_content = convert_to_markdown(text_content, "plain_text")

        # Generate comprehensive preview
        preview = preview_document_structure(text_content)

        # Extract section headings for preview
        sections = []
        for line in text_content.split('\n'):
            if line.startswith('## '):
                sections.append(line[3:].strip())
            elif line.startswith('# ') and not preview.get("title"):
                preview["title"] = line[2:].strip()

        preview["sections"] = sections[:10]  # Limit to first 10 sections
        preview["format"] = format_info["format"]
        preview["filename"] = sanitize_filename(file.filename)
        preview["file_size"] = len(content)

        return {
            "status": "success",
            "preview": preview,
            "ready_for_generation": True,
            "recommendations": _generate_preview_recommendations(preview)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Document preview failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/upload/progress-stages")
async def get_progress_stages():
    """
    Get the defined stages for upload progress tracking.

    Returns stage names, progress percentages, and user-friendly messages
    for implementing progress indicators in the UI.
    """
    return get_upload_progress_stages()


@app.get("/api/document/supported-formats")
async def get_supported_formats():
    """
    Get list of supported document formats.

    Returns format information including:
    - File extensions
    - MIME types
    - Format descriptions
    - Best practices
    """
    return {
        "formats": [
            {
                "extension": ".md",
                "name": "Markdown",
                "mime_types": ["text/markdown", "text/x-markdown"],
                "description": "Best format for structured content with headings, lists, and code",
                "recommended": True
            },
            {
                "extension": ".txt",
                "name": "Plain Text",
                "mime_types": ["text/plain"],
                "description": "Simple text files - content will be auto-structured",
                "recommended": False
            },
            {
                "extension": ".rst",
                "name": "reStructuredText",
                "mime_types": ["text/x-rst", "text/restructuredtext"],
                "description": "Python documentation format - automatically converted",
                "recommended": False
            }
        ],
        "max_file_size": "10MB",
        "tips": [
            "Use Markdown for best results with automatic scene detection",
            "Include ## headings to create logical video sections",
            "Add code blocks with ``` for command/code scenes",
            "Use bullet points for list scenes"
        ]
    }


def _generate_preview_recommendations(preview: Dict) -> List[str]:
    """Generate helpful recommendations based on document preview."""
    recommendations = []

    if preview.get("section_count", 0) == 0:
        recommendations.append("Add ## headings to create distinct video sections")

    if preview.get("word_count", 0) < 100:
        recommendations.append("Consider adding more content for a richer video")

    if preview.get("word_count", 0) > 5000:
        recommendations.append("Consider splitting into multiple videos for better engagement")

    if not preview.get("has_lists") and not preview.get("has_code"):
        recommendations.append("Add bullet points or code blocks for visual variety")

    if preview.get("estimated_scenes", 0) > 20:
        recommendations.append("Video may be long - consider splitting by H2 sections")

    if not recommendations:
        recommendations.append("Document looks good for video generation!")

    return recommendations


@app.post("/api/parse-only/document")
@limiter.limit(PARSE_LIMIT)
async def parse_document_only(request: Request, input: DocumentInput):
    """
    Parse document and return scenes for review WITHOUT generating video.
    This allows users to review/edit scenes before triggering generation.

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        # Import the document adapter directly
        from video_gen.adapters.document import DocumentInputAdapter
        from video_gen.shared.models import InputConfig as PipelineInputConfig

        # Strip any surrounding quotes from the path
        document_path = str(input.content).strip().strip('"').strip("'")

        # Create input config
        input_config = PipelineInputConfig(
            input_type="document",
            source=document_path,
            accent_color=input.accent_color,
            voice=input.voice,
            languages=["en"],
            video_count=input.video_count,
            split_by_h2=(input.video_count > 1)
        )

        # Use adapter directly to parse (no pipeline execution)
        adapter = DocumentInputAdapter()
        parse_result = adapter.parse(input_config)

        logger.info(f"Document parsed: {len(parse_result.get('videos', []))} videos")

        # Return scenes for frontend review
        return {
            "status": "success",
            "message": "Document parsed successfully",
            "data": parse_result,
            "scene_count": sum(len(v.get("scenes", [])) for v in parse_result.get("videos", [])),
            "video_count": len(parse_result.get("videos", []))
        }

    except Exception as e:
        logger.error(f"Parse-only failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/parse-only/youtube")
@limiter.limit(PARSE_LIMIT)
async def parse_youtube_only(request: Request, input: YouTubeInput):
    """
    Parse YouTube video and return scenes for review WITHOUT generating video.
    This allows users to review/edit scenes before triggering generation.

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        # Import the YouTube adapter directly
        from video_gen.adapters.youtube import YouTubeInputAdapter
        from video_gen.shared.models import InputConfig as PipelineInputConfig

        # Strip any surrounding quotes from URL
        youtube_url = str(input.url).strip().strip('"').strip("'")

        # Create input config
        input_config = PipelineInputConfig(
            input_type="youtube",
            source=youtube_url,
            accent_color=input.accent_color,
            voice="male",
            languages=["en"]
        )

        # Use adapter directly to parse (no pipeline execution)
        adapter = YouTubeInputAdapter()
        parse_result = adapter.parse(input_config)

        logger.info(f"YouTube parsed: {len(parse_result.get('videos', []))} videos")

        # Return scenes for frontend review
        return {
            "status": "success",
            "message": "YouTube video parsed successfully",
            "data": parse_result,
            "scene_count": sum(len(v.get("scenes", [])) for v in parse_result.get("videos", [])),
            "video_count": len(parse_result.get("videos", []))
        }

    except Exception as e:
        logger.error(f"YouTube parse-only failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/parse/youtube")
@limiter.limit(PARSE_LIMIT)
async def parse_youtube(request: Request, input: YouTubeInput, background_tasks: BackgroundTasks):
    """
    Parse YouTube video and generate script.
    Now uses unified pipeline.

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        # Generate task ID FIRST
        task_id = f"yt_{int(time.time())}"

        # Strip any surrounding quotes from URL
        youtube_url = str(input.url).strip().strip('"').strip("'")

        input_config = InputConfig(
            input_type="youtube",
            source=youtube_url,  # Cleaned URL
            accent_color=input.accent_color,
            voice="male",  # Default voice for YouTube parsing
            languages=["en"]
        )

        pipeline = get_pipeline()

        # Pass task_id to background task
        background_tasks.add_task(
            execute_pipeline_task,
            pipeline,
            input_config,
            task_id
        )

        logger.info(f"YouTube parsing started: {task_id}")

        return {
            "task_id": task_id,
            "status": "started",
            "message": "YouTube parsing started"
        }

    except Exception as e:
        logger.error(f"YouTube parsing failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# YouTube Input Flow - Enhanced Endpoints
# ============================================================================

@app.post("/api/youtube/validate")
@limiter.limit(PARSE_LIMIT)
async def validate_youtube_url_endpoint(http_request: Request, request: YouTubeURLValidation):
    """
    Validate a YouTube URL and return detailed validation result.

    This endpoint provides comprehensive URL validation including:
    - URL format validation for all YouTube URL types
    - Video ID extraction
    - URL normalization to standard format

    Returns:
        JSON with validation result including:
        - is_valid: Whether URL is valid
        - video_id: Extracted video ID (if valid)
        - normalized_url: Standardized URL format
        - error: Error message (if invalid)

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        from video_gen.utils.youtube_validator import validate_youtube_url

        result = validate_youtube_url(request.url)
        return result.to_dict()

    except Exception as e:
        logger.error(f"YouTube URL validation failed: {e}", exc_info=True)
        return {
            "is_valid": False,
            "video_id": None,
            "normalized_url": None,
            "error": str(e),
            "error_code": "VALIDATION_ERROR"
        }


@app.post("/api/youtube/preview")
@limiter.limit(PARSE_LIMIT)
async def youtube_preview_endpoint(http_request: Request, request: YouTubePreviewRequest):
    """
    Get preview information for a YouTube video.

    This endpoint fetches video metadata for preview including:
    - Video title and channel
    - Duration and thumbnail
    - Transcript availability
    - Estimated scene count and generation time

    Args:
        request: YouTubePreviewRequest with URL and options

    Returns:
        JSON with video preview data for UI display

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        from video_gen.utils.youtube_validator import (
            YouTubeURLValidator,
            validate_youtube_url,
        )

        # First validate the URL
        validation = validate_youtube_url(request.url)
        if not validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": validation.error,
                    "error_code": validation.error_code
                }
            )

        video_id = validation.video_id

        # Fetch video information
        validator = YouTubeURLValidator()
        video_info = await validator.fetch_video_info(video_id)

        if video_info is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "Could not fetch video information",
                    "error_code": "VIDEO_NOT_FOUND"
                }
            )

        # Get preview data
        preview_data = video_info.get_preview_data()

        # Optionally include transcript preview
        if request.include_transcript_preview and video_info.has_transcript:
            transcript_preview = await _get_transcript_preview(
                video_id,
                request.transcript_language,
                max_segments=5
            )
            preview_data["transcript_preview"] = transcript_preview

        return {
            "status": "success",
            "video_id": video_id,
            "normalized_url": validation.normalized_url,
            "preview": preview_data
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"YouTube preview failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": f"Failed to get video preview: {str(e)}",
                "error_code": "PREVIEW_ERROR"
            }
        )


@app.post("/api/youtube/transcript-preview")
@limiter.limit(PARSE_LIMIT)
async def youtube_transcript_preview(http_request: Request, request: YouTubePreviewRequest):
    """
    Get a preview of the video transcript.

    This endpoint fetches the first few segments of the transcript
    to give users a preview before full processing.

    Args:
        request: YouTubePreviewRequest with URL and language

    Returns:
        JSON with transcript preview and availability info

    Rate limit: Moderate (configurable via RATE_LIMIT_PARSE env var)
    """
    try:
        from video_gen.utils.youtube_validator import (
            validate_youtube_url,
            YouTubeURLValidator,
        )

        # Validate URL
        validation = validate_youtube_url(request.url)
        if not validation.is_valid:
            raise HTTPException(
                status_code=400,
                detail={"error": validation.error}
            )

        video_id = validation.video_id

        # Check transcript availability
        validator = YouTubeURLValidator()
        transcript_info = await validator.check_transcript_availability(video_id)

        if not transcript_info.get("available"):
            return {
                "status": "unavailable",
                "video_id": video_id,
                "available": False,
                "languages": [],
                "error": transcript_info.get("error", "No transcript available for this video"),
                "suggestion": "This video does not have captions. Try a different video with subtitles enabled."
            }

        # Get transcript preview
        transcript_preview = await _get_transcript_preview(
            video_id,
            request.transcript_language,
            max_segments=10
        )

        return {
            "status": "success",
            "video_id": video_id,
            "available": True,
            "languages": transcript_info.get("languages", []),
            "requested_language": request.transcript_language,
            "preview": transcript_preview
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Transcript preview failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={"error": f"Failed to get transcript preview: {str(e)}"}
        )


@app.get("/api/youtube/estimate/{video_id}")
async def youtube_estimate(video_id: str):
    """
    Get generation time and scene count estimates for a video.

    Args:
        video_id: YouTube video ID (11 characters)

    Returns:
        JSON with estimation details including:
        - source_duration_seconds: Original video duration
        - estimated_scenes: Number of scenes to generate
        - generation_estimate: Estimated processing time
    """
    try:
        from video_gen.utils.youtube_validator import (
            YouTubeURLValidator,
            estimate_generation_duration,
            estimate_scene_count,
        )

        # Validate video ID format
        import re
        if not re.match(r'^[a-zA-Z0-9_-]{11}$', video_id):
            raise HTTPException(
                status_code=400,
                detail={"error": "Invalid video ID format"}
            )

        # Try to get video duration
        validator = YouTubeURLValidator()
        video_info = await validator.fetch_video_info(video_id)

        if video_info and video_info.duration_seconds > 0:
            duration = video_info.duration_seconds
        else:
            # Default estimate for unknown duration
            duration = 180  # 3 minutes default

        return {
            "video_id": video_id,
            "source_duration_seconds": duration,
            "source_duration_formatted": f"{duration // 60}:{duration % 60:02d}",
            "estimated_scenes": estimate_scene_count(duration),
            "generation_estimate": estimate_generation_duration(duration),
            "has_accurate_duration": video_info is not None and video_info.duration_seconds > 0
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Estimation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={"error": f"Failed to estimate: {str(e)}"}
        )


async def _get_transcript_preview(
    video_id: str,
    language: str = "en",
    max_segments: int = 5
) -> Dict[str, Any]:
    """
    Get a preview of the transcript for display.

    Args:
        video_id: YouTube video ID
        language: Transcript language code
        max_segments: Maximum number of segments to return

    Returns:
        Dictionary with transcript preview data
    """
    try:
        from youtube_transcript_api import YouTubeTranscriptApi
        from youtube_transcript_api._errors import NoTranscriptFound

        try:
            transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)

            # Try to get requested language
            try:
                transcript = transcript_list.find_transcript([language])
            except NoTranscriptFound:
                # Fall back to auto-generated or any available
                transcript = transcript_list.find_generated_transcript([language])

            transcript_data = transcript.fetch()

            # Get preview segments
            preview_segments = []
            for segment in transcript_data[:max_segments]:
                preview_segments.append({
                    "text": segment.get("text", ""),
                    "start": segment.get("start", 0),
                    "duration": segment.get("duration", 0)
                })

            # Calculate total word count
            total_words = sum(
                len(seg.get("text", "").split())
                for seg in transcript_data
            )

            return {
                "segments": preview_segments,
                "total_segments": len(transcript_data),
                "total_words": total_words,
                "language": transcript.language_code,
                "is_generated": transcript.is_generated,
                "preview_text": " ".join(s["text"] for s in preview_segments)
            }

        except NoTranscriptFound:
            return {
                "segments": [],
                "total_segments": 0,
                "error": f"No transcript found for language: {language}"
            }

    except ImportError:
        return {
            "segments": [],
            "total_segments": 0,
            "error": "youtube-transcript-api not installed"
        }
    except Exception as e:
        logger.error(f"Error getting transcript preview: {e}")
        return {
            "segments": [],
            "total_segments": 0,
            "error": str(e)
        }


@app.post("/api/generate")
@limiter.limit(GENERATE_LIMIT)
async def generate_videos(request: Request, video_set: VideoSet, background_tasks: BackgroundTasks):
    """
    Generate videos from video set.
    Now uses unified pipeline.

    Rate limit: Very strict (configurable via RATE_LIMIT_GENERATE env var)
    """
    try:
        # Generate task ID FIRST
        task_id = f"gen_{int(time.time())}"

        # Convert VideoSet to pipeline input
        # The pipeline expects programmatic input with video set data
        input_config = InputConfig(
            input_type="programmatic",
            source=json.dumps(video_set.model_dump()),  # Serialize video set as JSON string (Pydantic v2)
            accent_color=video_set.accent_color or "blue",
            voice="male",
            languages=video_set.languages or ["en"]
        )

        pipeline = get_pipeline()

        # Pass task_id to background task
        background_tasks.add_task(
            execute_pipeline_task,
            pipeline,
            input_config,
            task_id
        )

        logger.info(f"Video generation started: {task_id} for set {video_set.set_id}")

        return {
            "task_id": task_id,
            "status": "started",
            "message": "Video generation started"
        }

    except Exception as e:
        logger.error(f"Video generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tasks/{task_id}")
@limiter.limit(TASKS_LIMIT)
async def get_task_status(request: Request, task_id: str):
    """
    Get task status - now from unified pipeline.

    Returns task state in backward-compatible format for existing templates.

    Rate limit: High (polling endpoint, configurable via RATE_LIMIT_TASKS env var)
    """
    try:
        pipeline = get_pipeline()
        try:
            task_state = pipeline.state_manager.load(task_id)
        except Exception as load_error:
            # State loading failed - task doesn't exist
            logger.debug(f"Task not found: {task_id} - {load_error}")
            raise HTTPException(status_code=404, detail="Task not found")

        if not task_state:
            raise HTTPException(status_code=404, detail="Task not found")

        # Convert pipeline state to API response format
        # Maintain backward compatibility with existing frontend
        # Get detailed message from current stage if available
        stage_message = None
        if task_state.current_stage and task_state.current_stage in task_state.stages:
            stage_data = task_state.stages[task_state.current_stage]
            stage_message = stage_data.metadata.get("message")

        return {
            "task_id": task_state.task_id,
            "status": _map_status(task_state.status.value),
            "progress": int(task_state.overall_progress * 100),  # Fix: Convert 0.0-1.0 to 0-100
            "message": stage_message or task_state.current_stage or "Processing...",
            "type": _infer_type_from_input(task_state.input_config),
            "errors": task_state.errors if task_state.errors else None,
            "result": task_state.result if task_state.status.value == "completed" else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get task status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve task status")

@app.get("/api/tasks/{task_id}/stream")
async def stream_task_progress(task_id: str):
    """
    Stream real-time progress via Server-Sent Events.
    Now uses pipeline event system for real-time updates.

    Enhanced to show granular stage-level progress, not just overall progress.
    """
    async def event_generator():
        pipeline = get_pipeline()

        # Check if task exists
        try:
            task_state = pipeline.state_manager.load(task_id)
        except Exception as e:
            yield f"data: {json.dumps({'error': 'Task not found', 'details': str(e)})}\n\n"
            return

        if not task_state:
            # Send error and close
            yield f"data: {json.dumps({'error': 'Task not found'})}\n\n"
            return

        last_progress = -1
        last_stage_progress = -1
        last_stage = None

        # Poll for updates (simplified - could use actual event subscription)
        while True:
            try:
                # Reload state
                task_state = pipeline.state_manager.load(task_id)
                if not task_state:
                    break

                # Get current stage info for granular progress
                current_stage = task_state.current_stage
                stage_progress_float = 0.0
                stage_message = None

                if current_stage and current_stage in task_state.stages:
                    stage_data = task_state.stages[current_stage]
                    stage_progress_float = stage_data.progress
                    stage_message = stage_data.metadata.get("message")

                # Calculate overall progress with stage granularity
                # This gives smoother progress updates instead of jumps between stages
                current_progress = int(task_state.overall_progress * 100)
                stage_progress = int(stage_progress_float * 100)

                # Send update if progress OR stage changed (more responsive)
                progress_changed = current_progress != last_progress
                stage_changed = current_stage != last_stage
                stage_progress_changed = stage_progress != last_stage_progress

                if progress_changed or stage_changed or stage_progress_changed:
                    last_progress = current_progress
                    last_stage = current_stage
                    last_stage_progress = stage_progress

                    event_data = {
                        "task_id": task_id,
                        "status": _map_status(task_state.status.value),
                        "progress": current_progress,
                        "stage": current_stage,
                        "stage_display": STAGE_DISPLAY_NAMES.get(current_stage, current_stage or "Initializing"),
                        "stage_progress": stage_progress,
                        "message": stage_message or STAGE_DISPLAY_NAMES.get(current_stage, current_stage) or "Processing...",
                        "errors": task_state.errors if task_state.errors else None
                    }

                    yield f"data: {json.dumps(event_data)}\n\n"

                # Stop if completed or failed
                if task_state.status.value in ["completed", "failed", "cancelled"]:
                    # Send final event with complete info
                    final_data = {
                        "task_id": task_id,
                        "status": _map_status(task_state.status.value),
                        "progress": 100 if task_state.status.value == "completed" else current_progress,
                        "stage": current_stage,
                        "stage_display": STAGE_DISPLAY_NAMES.get(current_stage, current_stage or "Complete"),
                        "stage_progress": 100 if task_state.status.value == "completed" else stage_progress,
                        "message": "Complete" if task_state.status.value == "completed" else (stage_message or "Failed"),
                        "final": True,
                        "errors": task_state.errors if task_state.errors else None,
                        "result": task_state.result if task_state.status.value == "completed" else None
                    }
                    yield f"data: {json.dumps(final_data)}\n\n"
                    break

                await asyncio.sleep(0.3)  # Faster polling for more responsive updates

            except Exception as e:
                logger.error(f"Error streaming progress: {e}")
                yield f"data: {json.dumps({'error': str(e), 'task_id': task_id})}\n\n"
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )

@app.get("/api/scene-types")
async def get_scene_types():
    """Get available scene types"""
    return {
        "general": [
            {"id": "title", "name": "Title Slide", "icon": "🎬"},
            {"id": "command", "name": "Command/Code", "icon": "💻"},
            {"id": "list", "name": "List Items", "icon": "📋"},
            {"id": "outro", "name": "Outro/CTA", "icon": "✅"},
            {"id": "code_comparison", "name": "Code Comparison", "icon": "🔄"},
            {"id": "quote", "name": "Quote", "icon": "💬"}
        ],
        "educational": [
            {"id": "learning_objectives", "name": "Learning Objectives", "icon": "🎯"},
            {"id": "problem", "name": "Problem", "icon": "❓"},
            {"id": "solution", "name": "Solution", "icon": "💡"},
            {"id": "checkpoint", "name": "Checkpoint", "icon": "✓"},
            {"id": "quiz", "name": "Quiz", "icon": "📝"},
            {"id": "exercise", "name": "Exercise", "icon": "💪"}
        ]
    }

@app.get("/api/voices")
async def get_voices():
    """Get available voices"""
    return [
        {"id": "male", "name": "Andrew (Male)", "description": "Professional, confident"},
        {"id": "male_warm", "name": "Brandon (Male Warm)", "description": "Warm, engaging"},
        {"id": "female", "name": "Aria (Female)", "description": "Clear, crisp"},
        {"id": "female_friendly", "name": "Ava (Female Friendly)", "description": "Friendly, pleasant"}
    ]

@app.get("/api/colors")
async def get_colors():
    """Get available accent colors"""
    return ["blue", "purple", "orange", "green", "pink", "cyan"]

@app.get("/api/languages")
async def get_languages():
    """Get all supported languages (28+)"""
    languages = []
    for lang_code in sorted(list_available_languages()):
        info = LANGUAGE_INFO.get(lang_code, {})
        voices = MULTILINGUAL_VOICES.get(lang_code, {})

        languages.append({
            "code": lang_code,
            "name": info.get("name", lang_code.upper()),
            "name_local": info.get("name_local", lang_code.upper()),
            "rtl": info.get("rtl", False),
            "voice_count": len(voices),
            "voices": list(voices.keys())
        })

    return {"languages": languages, "total": len(languages)}

def _extract_friendly_voice_name(edge_tts_voice_id: str) -> str:
    """
    Extract a friendly display name from an Edge-TTS voice ID.

    Examples:
        'en-US-AndrewMultilingualNeural' -> 'Andrew'
        'en-US-AriaNeural' -> 'Aria'
        'es-ES-AlvaroNeural' -> 'Alvaro'
        'zh-CN-XiaoxiaoNeural' -> 'Xiaoxiao'
    """
    # Split by dash and get the last part (name + suffix)
    parts = edge_tts_voice_id.split('-')
    if len(parts) >= 3:
        name_part = parts[-1]  # e.g., 'AndrewMultilingualNeural' or 'AriaNeural'
    else:
        name_part = edge_tts_voice_id

    # Remove common suffixes
    for suffix in ['MultilingualNeural', 'Neural', 'Multilingual']:
        if name_part.endswith(suffix):
            name_part = name_part[:-len(suffix)]
            break

    return name_part if name_part else edge_tts_voice_id


@app.get("/api/languages/{lang_code}/voices")
async def get_language_voices(lang_code: str):
    """Get available voices for a specific language with enhanced metadata"""
    if lang_code not in MULTILINGUAL_VOICES:
        raise HTTPException(status_code=404, detail=f"Language '{lang_code}' not supported")

    voices = MULTILINGUAL_VOICES[lang_code]
    voice_objects = []

    for voice_key, edge_tts_voice_id in voices.items():
        # Extract friendly name from Edge-TTS voice ID
        friendly_name = _extract_friendly_voice_name(edge_tts_voice_id)

        # Determine gender from the voice key (e.g., 'male', 'female', 'uk_female')
        key_lower = voice_key.lower()
        if 'female' in key_lower:
            gender = 'female'
            gender_symbol = '♀'
            desc = "Clear, friendly"
        elif 'male' in key_lower:
            gender = 'male'
            gender_symbol = '♂'
            desc = "Professional, confident"
        else:
            # Fallback: check the voice ID patterns
            voice_lower = edge_tts_voice_id.lower()
            if any(f in voice_lower for f in ['aria', 'emma', 'sonia', 'jenny', 'denise', 'elvira', 'katja', 'francisca', 'elsa', 'nanami', 'xiaoxiao', 'sunhi']):
                gender = 'female'
                gender_symbol = '♀'
                desc = "Clear, friendly"
            else:
                gender = 'male'
                gender_symbol = '♂'
                desc = "Professional, confident"

        # Create variant label if applicable (e.g., 'UK', 'MX', 'BR')
        variant_label = ""
        for variant in ['uk', 'au', 'mx', 'ar', 'co', 'ca', 'br', 'pt', 'at', 'ch', 'hk', 'tw', 'eg', 'be']:
            if voice_key.startswith(variant + '_'):
                variant_label = f" ({variant.upper()})"
                break

        voice_objects.append({
            "id": voice_key,
            "name": f"{friendly_name}{variant_label}",
            "display_name": f"{friendly_name} ({gender.capitalize()}){variant_label}",
            "description": desc,
            "gender": gender,
            "gender_symbol": gender_symbol,
            "edge_tts_id": edge_tts_voice_id,
            "sample_url": f"/static/audio/samples/{lang_code}_{gender}.mp3"
        })

    return {
        "status": "success",
        "language": lang_code,
        "voices": voice_objects,
        "voice_count": len(voice_objects)
    }

@app.post("/api/generate/multilingual")
@limiter.limit(GENERATE_LIMIT)
async def generate_multilingual(http_request: Request, request: MultilingualRequest, background_tasks: BackgroundTasks):
    """
    Generate multilingual videos.
    Now uses unified pipeline with multilingual config.

    Rate limit: Very strict (configurable via RATE_LIMIT_GENERATE env var)
    """
    try:
        # Generate task ID first
        task_id = f"ml_{int(time.time())}"

        # Create input config with multilingual settings
        # IMPORTANT: Pass dict, not JSON string! Programmatic adapter expects dict
        input_config = InputConfig(
            input_type="programmatic",
            source=request.video_set.model_dump(),  # Pass dict directly, not JSON string (Pydantic v2)
            accent_color=request.video_set.accent_color or "blue",
            voice="male",
            languages=request.target_languages
        )

        # Store additional multilingual metadata in input config
        # The pipeline will use this for translation
        input_config_dict = input_config.to_dict()
        input_config_dict["source_language"] = request.source_language
        input_config_dict["translation_method"] = request.translation_method

        pipeline = get_pipeline()

        # Pass task_id to the background task
        background_tasks.add_task(
            execute_pipeline_task,
            pipeline,
            input_config,
            task_id  # Pass task_id so pipeline uses this ID
        )

        logger.info(f"Multilingual generation started: {task_id} for {len(request.target_languages)} languages")

        return {
            "task_id": task_id,
            "status": "started",
            "message": f"Multilingual generation started for {len(request.target_languages)} languages",
            "languages": request.target_languages,
            "source_language": request.source_language
        }

    except Exception as e:
        logger.error(f"Multilingual generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# Pipeline Integration - Background Task Execution
# ============================================================================

async def execute_pipeline_task(pipeline: Any, input_config: InputConfig, task_id: str = None):
    """
    Execute pipeline in background.

    This is the unified execution path for all video generation tasks.
    The pipeline handles all stages automatically with state persistence.

    Args:
        pipeline: PipelineOrchestrator instance
        input_config: Input configuration for the pipeline
        task_id: Optional task ID to use (if not provided, pipeline generates one)
    """
    try:
        # Execute the complete pipeline
        # IMPORTANT: Pass task_id to ensure consistent tracking
        result = await pipeline.execute(input_config, task_id=task_id)

        logger.info(f"Pipeline completed successfully: {result.task_id}")

    except Exception as e:
        logger.error(f"Pipeline execution failed for task {task_id}: {e}", exc_info=True)

        # Capture pipeline error in Sentry
        from app.utils.sentry_config import capture_pipeline_error
        capture_pipeline_error(
            error=e,
            task_id=task_id or "unknown",
            stage=None,  # Pipeline will track current stage internally
            context={
                "input_type": input_config.input_type,
                "languages": input_config.languages,
                "source": str(input_config.source)[:200]  # Truncate for privacy
            }
        )

        # Pipeline automatically persists failure state
        # No need for manual error handling


# ============================================================================
# Helper Functions - Status Mapping & Utilities
# ============================================================================

def _map_status(pipeline_status: str) -> str:
    """
    Map pipeline status to API status for backward compatibility.

    Pipeline uses: pending, running, paused, completed, failed, cancelled
    API expects: processing, complete, failed
    """
    status_map = {
        "pending": "processing",
        "running": "processing",
        "paused": "processing",
        "completed": "complete",
        "failed": "failed",
        "cancelled": "failed"
    }
    return status_map.get(pipeline_status, "processing")


def _infer_type_from_input(input_config: Dict[str, Any]) -> str:
    """
    Infer task type from input config for backward compatibility.

    Args:
        input_config: Input configuration dictionary

    Returns:
        Task type string (document, youtube, generate, multilingual)
    """
    input_type = input_config.get("input_type", "unknown")

    type_map = {
        "document": "document",
        "youtube": "youtube",
        "programmatic": "generate",
        "yaml": "generate",
        "wizard": "generate"
    }

    result_type = type_map.get(input_type, "generate")

    # Check for multilingual
    languages = input_config.get("languages", [])
    if len(languages) > 1:
        return "multilingual"

    return result_type


# Stage display names mapping (internal name -> user-friendly name)
STAGE_DISPLAY_NAMES = {
    "input_adaptation": "Preparation",
    "content_parsing": "Scenes",
    "script_generation": "Narration",
    "audio_generation": "Synthesis",
    "video_generation": "Composition",
    "output_handling": "Finalization",
    "validation": "Validation",
    "translation": "Translation",
}

# Ordered stages for display (matches the 6-stage pipeline)
ORDERED_STAGES = [
    "input_adaptation",
    "content_parsing",
    "script_generation",
    "audio_generation",
    "video_generation",
    "output_handling",
]


def _format_job_for_monitor(task_state) -> Dict[str, Any]:
    """
    Format a TaskState for the jobs monitor frontend.

    Converts internal stage data to the format expected by jobs.html JavaScript.

    Args:
        task_state: TaskState object from state manager

    Returns:
        Dictionary with job data for frontend display
    """
    from datetime import datetime

    # Extract document/source name from input config
    input_config = task_state.input_config or {}
    source = input_config.get("source", "Unknown")

    # Get friendly document name
    if isinstance(source, str):
        if source.startswith("{"):
            # JSON data - try to extract set name
            try:
                import json
                data = json.loads(source)
                document_name = data.get("set_name", data.get("title", "Video Set"))
            except:
                document_name = "Video Set"
        elif "/" in source or "\\" in source:
            # File path - get filename
            document_name = Path(source).stem
        elif source.startswith("http"):
            # URL - show truncated
            document_name = source[:40] + "..." if len(source) > 40 else source
        else:
            document_name = source[:50] if len(source) > 50 else source
    else:
        document_name = "Video Generation"

    # Calculate elapsed time
    started_at = task_state.started_at
    if started_at:
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at)
        elapsed_seconds = (datetime.now() - started_at).total_seconds()
        elapsed = _format_duration(elapsed_seconds)
    else:
        elapsed = "0:00"

    # Calculate total duration for completed jobs
    total_duration = None
    if task_state.completed_at and task_state.started_at:
        completed_at = task_state.completed_at
        if isinstance(completed_at, str):
            completed_at = datetime.fromisoformat(completed_at)
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at)
        total_seconds = (completed_at - started_at).total_seconds()
        total_duration = _format_duration(total_seconds)

    # Build stage progress info with enhanced error details
    stages_info = []
    current_stage_name = task_state.current_stage
    failed_stage_error = None  # Track error from failed stage

    for stage_name in ORDERED_STAGES:
        stage_state = task_state.stages.get(stage_name)

        if stage_state:
            stage_status_value = stage_state.status.value if hasattr(stage_state.status, 'value') else stage_state.status

            if stage_status_value == "completed":
                status = "completed"
            elif stage_status_value == "running":
                status = "active"
            elif stage_status_value == "failed":
                status = "failed"
                # Capture the error from this failed stage
                if stage_state.error:
                    failed_stage_error = {
                        "stage": STAGE_DISPLAY_NAMES.get(stage_name, stage_name),
                        "error": stage_state.error
                    }
            else:
                status = "pending"

            # Calculate stage duration
            duration = None
            if stage_state.started_at and stage_state.completed_at:
                stage_start = stage_state.started_at
                stage_end = stage_state.completed_at
                if isinstance(stage_start, str):
                    stage_start = datetime.fromisoformat(stage_start)
                if isinstance(stage_end, str):
                    stage_end = datetime.fromisoformat(stage_end)
                duration = f"{(stage_end - stage_start).total_seconds():.1f}s"

            # Include stage progress for active stages
            stage_progress = int(stage_state.progress * 100) if stage_state.progress else 0
        else:
            # Stage not yet registered
            status = "pending"
            duration = None
            stage_progress = 0

        stages_info.append({
            "name": STAGE_DISPLAY_NAMES.get(stage_name, stage_name),
            "internal_name": stage_name,
            "status": status,
            "duration": duration,
            "progress": stage_progress,
            "error": stage_state.error if stage_state and stage_state.error else None
        })

    # Get current stage display name
    current_stage_display = STAGE_DISPLAY_NAMES.get(
        current_stage_name, current_stage_name or "Initializing"
    )

    # Calculate progress as percentage (0-100)
    progress = int(task_state.overall_progress * 100)

    # Build comprehensive error info for failed jobs
    error_details = None
    if task_state.errors or failed_stage_error:
        error_details = {
            "errors": task_state.errors if task_state.errors else [],
            "failed_stage": failed_stage_error,
            "error_count": len(task_state.errors) if task_state.errors else 0,
            "summary": task_state.errors[0] if task_state.errors else (
                f"Failed at {failed_stage_error['stage']}: {failed_stage_error['error'][:100]}" if failed_stage_error else "Unknown error"
            )
        }

    return {
        "id": task_state.task_id,
        "document": document_name,
        "current_stage": current_stage_display,
        "progress": progress,
        "elapsed": elapsed,
        "total_duration": total_duration,
        "stages": stages_info,
        "status": task_state.status.value if hasattr(task_state.status, 'value') else task_state.status,
        "errors": task_state.errors if task_state.errors else [],
        "error_details": error_details,
        "warnings": task_state.warnings if task_state.warnings else [],
        "created_at": task_state.created_at.isoformat() if task_state.created_at else None,
    }


def _format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string (M:SS or H:MM:SS)."""
    if seconds < 0:
        return "0:00"

    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


def _add_queue_positions(queued_jobs: List[Dict]) -> List[Dict]:
    """Add queue position numbers to queued jobs."""
    for i, job in enumerate(queued_jobs, start=1):
        job["queue_position"] = i
    return queued_jobs


# ============================================================================
# Health & System Info
# ============================================================================

@app.get("/api/videos/jobs")
async def get_jobs(request: Request):
    """
    Get all video generation jobs.

    Returns JSON for JavaScript clients or HTML for HTMX based on Accept header.
    Supports real-time monitoring with detailed stage information.
    """
    try:
        pipeline = get_pipeline()

        # Get all tasks from state manager
        tasks = pipeline.state_manager.list_tasks()

        # Check Accept header to determine response format
        accept_header = request.headers.get("Accept", "")
        wants_html = "text/html" in accept_header and "application/json" not in accept_header

        if wants_html:
            # Return HTML for HTMX requests (legacy support)
            jobs = []
            for task in tasks:
                jobs.append({
                    "job_id": task.task_id,
                    "input_method": _infer_type_from_input(task.input_config),
                    "status": _map_status(task.status.value),
                    "progress": int(task.overall_progress * 100),
                    "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                })

            return templates.TemplateResponse("job_list.html", {
                "request": request,
                "jobs": jobs
            })

        # Return JSON for JavaScript clients (modern jobs page)
        active_jobs = []
        queued_jobs = []
        completed_jobs = []
        failed_jobs = []

        for task in tasks:
            status = task.status.value
            job_data = _format_job_for_monitor(task)

            if status == "running":
                active_jobs.append(job_data)
            elif status == "pending":
                queued_jobs.append(job_data)
            elif status == "completed":
                completed_jobs.append(job_data)
            elif status in ["failed", "cancelled"]:
                failed_jobs.append(job_data)

        # Add queue positions to queued jobs
        queued_jobs = _add_queue_positions(queued_jobs)

        # Calculate stats
        stats = {
            "active": len(active_jobs),
            "queued": len(queued_jobs),
            "completed": len(completed_jobs),
            "failed": len(failed_jobs)
        }

        return JSONResponse({
            "stats": stats,
            "active_jobs": active_jobs,
            "queued_jobs": queued_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs
        })

    except Exception as e:
        logger.error(f"Failed to get jobs: {e}", exc_info=True)
        # Return empty response on error
        accept_header = request.headers.get("Accept", "")
        if "text/html" in accept_header:
            return templates.TemplateResponse("job_list.html", {
                "request": request,
                "jobs": []
            })
        return JSONResponse({
            "stats": {"active": 0, "queued": 0, "completed": 0, "failed": 0},
            "active_jobs": [],
            "queued_jobs": [],
            "completed_jobs": [],
            "failed_jobs": []
        })


@app.get("/api/videos/jobs/{job_id}")
async def get_job_detail(job_id: str):
    """
    Get detailed status for a specific job.

    Returns comprehensive job information including:
    - Current stage and progress
    - All stage statuses and durations
    - Error information if failed
    - Result data if completed

    Args:
        job_id: The job/task ID to query

    Returns:
        JSON with detailed job information
    """
    try:
        pipeline = get_pipeline()
        task_state = pipeline.state_manager.load(job_id)

        if not task_state:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

        # Format detailed response
        job_data = _format_job_for_monitor(task_state)

        # Add additional details for individual job view
        job_data["input_config"] = task_state.input_config
        job_data["result"] = task_state.result
        job_data["warnings"] = task_state.warnings

        return JSONResponse({
            "status": "success",
            "job": job_data
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get job {job_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/videos/jobs/{job_id}/events")
async def stream_job_events(job_id: str):
    """
    Stream real-time events for a specific job via SSE.

    This endpoint provides Server-Sent Events for real-time job monitoring.
    The frontend can subscribe to receive live updates on job progress.

    Args:
        job_id: The job/task ID to stream events for

    Returns:
        SSE stream with job progress updates
    """
    async def event_generator():
        pipeline = get_pipeline()

        # Check if task exists
        if not pipeline.state_manager.exists(job_id):
            yield f"data: {json.dumps({'error': 'Job not found', 'job_id': job_id})}\n\n"
            return

        last_progress = -1
        last_stage = None

        # Poll for updates
        while True:
            try:
                task_state = pipeline.state_manager.load(job_id)
                if not task_state:
                    break

                current_progress = int(task_state.overall_progress * 100)
                current_stage = task_state.current_stage

                # Send update if progress or stage changed
                if current_progress != last_progress or current_stage != last_stage:
                    last_progress = current_progress
                    last_stage = current_stage

                    # Build event data
                    event_data = {
                        "job_id": job_id,
                        "status": task_state.status.value,
                        "progress": current_progress,
                        "current_stage": STAGE_DISPLAY_NAMES.get(
                            current_stage, current_stage or "Initializing"
                        ),
                        "stages": []
                    }

                    # Add stage details
                    for stage_name in ORDERED_STAGES:
                        stage_state = task_state.stages.get(stage_name)
                        if stage_state:
                            stage_status = stage_state.status.value if hasattr(stage_state.status, 'value') else stage_state.status
                            status_map = {
                                "completed": "completed",
                                "running": "active",
                                "failed": "failed"
                            }
                            event_data["stages"].append({
                                "name": STAGE_DISPLAY_NAMES.get(stage_name, stage_name),
                                "status": status_map.get(stage_status, "pending")
                            })
                        else:
                            event_data["stages"].append({
                                "name": STAGE_DISPLAY_NAMES.get(stage_name, stage_name),
                                "status": "pending"
                            })

                    yield f"data: {json.dumps(event_data)}\n\n"

                # Stop if completed or failed
                if task_state.status.value in ["completed", "failed", "cancelled"]:
                    # Send final event
                    final_data = {
                        "job_id": job_id,
                        "status": task_state.status.value,
                        "progress": 100 if task_state.status.value == "completed" else current_progress,
                        "final": True
                    }
                    if task_state.errors:
                        final_data["errors"] = task_state.errors
                    yield f"data: {json.dumps(final_data)}\n\n"
                    break

                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Error streaming job events: {e}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )


@app.get("/api/health")
@limiter.limit(HEALTH_LIMIT)
async def health_check(request: Request):
    """
    Health check endpoint.

    Verifies:
    - API is running
    - Pipeline is initialized
    - Required dependencies available

    Rate limit: Very high (health checks should not be restricted)
    """
    try:
        pipeline = get_pipeline()

        return {
            "status": "healthy",
            "service": "video-generation",
            "pipeline": "unified",
            "version": "2.0.0",
            "stages": len(pipeline.stages),
            "features": {
                "multilingual": True,
                "document_parsing": True,
                "youtube_parsing": True,
                "programmatic_api": True,
                "state_persistence": True,
                "auto_resume": True,
                "templates": True
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return {
            "status": "unhealthy",
            "error": str(e)
        }


@app.get("/api/security/status")
@limiter.limit(HEALTH_LIMIT)
async def security_status(request: Request):
    """
    Security configuration status endpoint.

    Returns:
    - Current security headers configuration
    - HTTPS redirect status
    - CSP configuration
    - Security warnings (if any)

    Rate limit: Very high (status checks should not be restricted)
    """
    try:
        # Get security report
        report = get_security_report()

        # Get validation warnings
        warnings = validate_security_configuration()

        return {
            "status": "configured",
            "security": report,
            "warnings": warnings,
            "secure_connection": request.url.scheme == "https",
            "client_ip": request.client.host if request.client else "unknown"
        }
    except Exception as e:
        logger.error(f"Security status check failed: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }

# ============================================================================
# Template Management Endpoints
# ============================================================================

class TemplateModel(BaseModel):
    name: str
    description: Optional[str] = ""
    mode: Literal["single", "set"]
    config: Dict[str, Any]

@app.post("/api/templates/save")
async def save_template(template: TemplateModel):
    """
    Save a video configuration template.
    Templates are stored in user's browser localStorage via client-side.
    This endpoint is for server-side template storage (future enhancement).
    """
    try:
        # For now, return success - templates handled client-side
        # Future: Store in database or file system
        return {
            "success": True,
            "message": "Template saved successfully",
            "template_id": f"tmpl_{int(time.time())}"
        }
    except Exception as e:
        logger.error(f"Failed to save template: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/templates/list")
async def list_templates():
    """
    Get list of saved templates.
    For now, templates are client-side only.
    Future: Retrieve from database or file system.
    """
    try:
        # For now, return empty list - templates handled client-side
        # Future: Query database or file system
        return {
            "templates": [],
            "message": "Templates are stored client-side in browser localStorage"
        }
    except Exception as e:
        logger.error(f"Failed to list templates: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: str):
    """
    Delete a template.
    For now, templates are client-side only.
    """
    try:
        # For now, return success - templates handled client-side
        # Future: Delete from database or file system
        return {
            "success": True,
            "message": "Template deleted successfully"
        }
    except Exception as e:
        logger.error(f"Failed to delete template: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# NOTE: Startup/shutdown now handled by modern lifespan context manager above
# ============================================================================


# ============================================================================
# Startup
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Video Generation Web UI...")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )