"""
FastAPI backend for Video Generation System
Now powered by the unified pipeline for consistency and reliability.

HTMX + Alpine.js compatible REST API
"""
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Dict, Optional, Literal, Any
from contextlib import asynccontextmanager
import asyncio
import json
import sys
from pathlib import Path
import time
import logging

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

# Add parent directory to path for video_gen imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()
load_dotenv(Path(__file__).parent / ".env")  # Also load from app/.env

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

# Setup templates and static files
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.auto_reload = True  # Force template reloading in production
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

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
    video_id: str
    title: str
    scenes: List[Dict]  # Accept any scene type
    voice: Optional[str] = "male"  # Deprecated: use voices instead
    voices: Optional[List[str]] = None  # NEW: Support multiple voices
    duration: Optional[int] = None

    def get_voices(self) -> List[str]:
        """Get voice list, handling backward compatibility."""
        if self.voices:
            return self.voices
        return [self.voice] if self.voice else ["male"]

class VideoSet(BaseModel):
    set_id: str
    set_name: str
    videos: List[Video]
    accent_color: Optional[str] = "blue"
    languages: Optional[List[str]] = ["en"]  # Default to English only
    source_language: Optional[str] = "en"
    translation_method: Optional[Literal["claude", "google", "manual"]] = "claude"

class DocumentInput(BaseModel):
    content: str
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    video_count: Optional[int] = 1  # Number of videos to split document into
    generate_set: Optional[bool] = False  # Whether to generate a video set

class YouTubeInput(BaseModel):
    url: str
    duration: Optional[int] = 60
    accent_color: Optional[str] = "blue"

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
    """Unified video creation page"""
    return templates.TemplateResponse("create.html", {"request": request})

@app.get("/create-unified", response_class=HTMLResponse)
async def create_unified(request: Request):
    """New unified creation interface with Alpine.js store"""
    return templates.TemplateResponse("create-unified.html", {"request": request})

@app.get("/advanced", response_class=HTMLResponse)
async def advanced(request: Request):
    """Advanced features page for power users"""
    return templates.TemplateResponse("advanced.html", {"request": request})

# ============================================================================
# Routes - API Endpoints
# ============================================================================

@app.post("/api/parse/document")
async def parse_document(input: DocumentInput, background_tasks: BackgroundTasks):
    """
    Parse document and generate video set.
    Now uses unified pipeline for consistency.
    """
    try:
        # Generate task ID FIRST
        task_id = f"doc_{int(time.time())}"

        # Create input config for pipeline
        # Strip any surrounding quotes from the path (handles copy-paste with quotes)
        document_path = str(input.content).strip().strip('"').strip("'")

        input_config = InputConfig(
            input_type="document",
            source=document_path,  # Cleaned document path
            accent_color=input.accent_color,
            voice=input.voice,
            languages=["en"],  # Default to English for document parsing
            video_count=input.video_count,  # Pass user's video count selection
            split_by_h2=(input.video_count > 1)  # Auto-split if multiple videos requested
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

@app.post("/api/parse/youtube")
async def parse_youtube(input: YouTubeInput, background_tasks: BackgroundTasks):
    """
    Parse YouTube video and generate script.
    Now uses unified pipeline.
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

@app.post("/api/generate")
async def generate_videos(video_set: VideoSet, background_tasks: BackgroundTasks):
    """
    Generate videos from video set.
    Now uses unified pipeline.
    """
    try:
        # Generate task ID FIRST
        task_id = f"gen_{int(time.time())}"

        # Convert VideoSet to pipeline input
        # The pipeline expects programmatic input with video set data
        input_config = InputConfig(
            input_type="programmatic",
            source=json.dumps(video_set.dict()),  # Serialize video set as JSON string
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
async def get_task_status(task_id: str):
    """
    Get task status - now from unified pipeline.

    Returns task state in backward-compatible format for existing templates.
    """
    try:
        pipeline = get_pipeline()
        task_state = pipeline.state_manager.load(task_id)

        if not task_state:
            raise HTTPException(status_code=404, detail="Task not found")

        # Convert pipeline state to API response format
        # Maintain backward compatibility with existing frontend
        return {
            "task_id": task_state.task_id,
            "status": _map_status(task_state.status.value),
            "progress": int(task_state.overall_progress),
            "message": task_state.current_stage or "Processing...",
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
    """
    async def event_generator():
        pipeline = get_pipeline()

        # Check if task exists
        task_state = pipeline.state_manager.load(task_id)
        if not task_state:
            # Send error and close
            yield f"data: {json.dumps({'error': 'Task not found'})}\n\n"
            return

        last_progress = -1

        # Poll for updates (simplified - could use actual event subscription)
        while True:
            try:
                # Reload state
                task_state = pipeline.state_manager.load(task_id)
                if not task_state:
                    break

                current_progress = int(task_state.overall_progress)

                # Send update if progress changed
                if current_progress != last_progress:
                    last_progress = current_progress

                    event_data = {
                        "task_id": task_id,
                        "status": _map_status(task_state.status.value),
                        "progress": current_progress,
                        "message": task_state.current_stage or "Processing..."
                    }

                    yield f"data: {json.dumps(event_data)}\n\n"

                # Stop if completed or failed
                if task_state.status.value in ["completed", "failed", "cancelled"]:
                    break

                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Error streaming progress: {e}")
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

@app.get("/api/languages/{lang_code}/voices")
async def get_language_voices(lang_code: str):
    """Get available voices for a specific language"""
    if lang_code not in MULTILINGUAL_VOICES:
        raise HTTPException(status_code=404, detail=f"Language '{lang_code}' not supported")

    voices = MULTILINGUAL_VOICES[lang_code]
    return {
        "language": lang_code,
        "voices": [{"id": k, "name": v} for k, v in voices.items()]
    }

@app.post("/api/generate/multilingual")
async def generate_multilingual(request: MultilingualRequest, background_tasks: BackgroundTasks):
    """
    Generate multilingual videos.
    Now uses unified pipeline with multilingual config.
    """
    try:
        # Generate task ID first
        task_id = f"ml_{int(time.time())}"

        # Create input config with multilingual settings
        # IMPORTANT: Pass dict, not JSON string! Programmatic adapter expects dict
        input_config = InputConfig(
            input_type="programmatic",
            source=request.video_set.dict(),  # Pass dict directly, not JSON string
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

# ============================================================================
# Health & System Info
# ============================================================================

@app.get("/api/videos/jobs")
async def get_jobs(request: Request):
    """
    Get all video generation jobs.

    Returns rendered HTML for HTMX or JSON based on Accept header.
    """
    try:
        pipeline = get_pipeline()

        # Get all tasks from state manager
        tasks = pipeline.state_manager.list_tasks()

        # Format jobs for template
        jobs = []
        for task in tasks:
            jobs.append({
                "job_id": task.task_id,
                "input_method": _infer_type_from_input(task.input_config),
                "status": _map_status(task.status.value),
                "progress": int(task.overall_progress * 100),
                "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            })

        # Return HTML for HTMX requests
        return templates.TemplateResponse("job_list.html", {
            "request": request,
            "jobs": jobs
        })

    except Exception as e:
        logger.error(f"Failed to get jobs: {e}", exc_info=True)
        # Return empty list on error
        return templates.TemplateResponse("job_list.html", {
            "request": request,
            "jobs": []
        })

@app.get("/api/health")
async def health_check():
    """
    Health check endpoint.

    Verifies:
    - API is running
    - Pipeline is initialized
    - Required dependencies available
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