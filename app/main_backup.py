"""
FastAPI backend for Video Generation System
HTMX + Alpine.js compatible REST API
"""
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Dict, Optional, Literal
import asyncio
import json
import sys
from pathlib import Path
import time

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

app = FastAPI(title="Video Generation API")

# Setup templates and static files
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# In-memory task storage (replace with Redis in production)
tasks: Dict[str, Dict] = {}

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

class Video(BaseModel):
    video_id: str
    title: str
    scenes: List[Dict]  # Accept any scene type
    voice: Optional[str] = "male"

class VideoSet(BaseModel):
    set_id: str
    set_name: str
    videos: List[Video]
    accent_color: Optional[str] = "blue"

class DocumentInput(BaseModel):
    content: str
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"

class YouTubeInput(BaseModel):
    url: str
    duration: Optional[int] = 60
    accent_color: Optional[str] = "blue"

# ============================================================================
# Routes - UI Pages
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page - input method selection"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/builder", response_class=HTMLResponse)
async def builder(request: Request):
    """Scene builder interface"""
    return templates.TemplateResponse("builder.html", {"request": request})

# ============================================================================
# Routes - API Endpoints
# ============================================================================

@app.post("/api/parse/document")
async def parse_document(input: DocumentInput, background_tasks: BackgroundTasks):
    """Parse document and generate video set"""
    task_id = f"doc_{int(time.time())}"
    tasks[task_id] = {
        "status": "processing",
        "progress": 0,
        "message": "Parsing document...",
        "type": "document"
    }

    # Start background task
    background_tasks.add_task(process_document, task_id, input)

    return {"task_id": task_id, "status": "started"}

@app.post("/api/parse/youtube")
async def parse_youtube(input: YouTubeInput, background_tasks: BackgroundTasks):
    """Parse YouTube video and generate script"""
    task_id = f"yt_{int(time.time())}"
    tasks[task_id] = {
        "status": "processing",
        "progress": 0,
        "message": "Fetching YouTube transcript...",
        "type": "youtube"
    }

    background_tasks.add_task(process_youtube, task_id, input)

    return {"task_id": task_id, "status": "started"}

@app.post("/api/generate")
async def generate_videos(video_set: VideoSet, background_tasks: BackgroundTasks):
    """Generate videos from video set"""
    task_id = f"gen_{int(time.time())}"
    tasks[task_id] = {
        "status": "processing",
        "progress": 0,
        "message": "Starting video generation...",
        "type": "generate",
        "set_id": video_set.set_id
    }

    background_tasks.add_task(process_generation, task_id, video_set)

    return {"task_id": task_id, "status": "started"}

@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Get task status"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    return tasks[task_id]

@app.get("/api/tasks/{task_id}/stream")
async def stream_task_progress(task_id: str):
    """Server-Sent Events stream for task progress"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    async def event_generator():
        last_progress = -1
        while True:
            task = tasks.get(task_id)
            if not task:
                break

            # Send update if progress changed
            if task["progress"] != last_progress:
                last_progress = task["progress"]
                yield f"data: {json.dumps(task)}\n\n"

            # Stop if complete or failed
            if task["status"] in ["complete", "failed"]:
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
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

# ============================================================================
# Background Tasks
# ============================================================================

async def process_document(task_id: str, input: DocumentInput):
    """Process document in background"""
    try:
        tasks[task_id]["progress"] = 20
        tasks[task_id]["message"] = "Parsing content..."

        # Simulate processing
        await asyncio.sleep(2)

        tasks[task_id]["progress"] = 80
        tasks[task_id]["message"] = "Finalizing..."

        await asyncio.sleep(1)

        tasks[task_id]["status"] = "complete"
        tasks[task_id]["progress"] = 100
        tasks[task_id]["message"] = "Document parsed successfully!"
        tasks[task_id]["result"] = {"set_id": "parsed_document"}

    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["message"] = str(e)

async def process_youtube(task_id: str, input: YouTubeInput):
    """Process YouTube URL in background"""
    try:
        tasks[task_id]["progress"] = 20
        tasks[task_id]["message"] = "Fetching transcript..."

        await asyncio.sleep(2)

        tasks[task_id]["progress"] = 60
        tasks[task_id]["message"] = "Generating scenes..."

        await asyncio.sleep(2)

        tasks[task_id]["status"] = "complete"
        tasks[task_id]["progress"] = 100
        tasks[task_id]["message"] = "YouTube video parsed!"
        tasks[task_id]["result"] = {"set_id": "youtube_video"}

    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["message"] = str(e)

async def process_generation(task_id: str, video_set: VideoSet):
    """Generate videos in background"""
    try:
        tasks[task_id]["progress"] = 30
        tasks[task_id]["message"] = "Generating audio..."

        await asyncio.sleep(3)

        tasks[task_id]["progress"] = 70
        tasks[task_id]["message"] = "Rendering videos..."

        await asyncio.sleep(3)

        tasks[task_id]["status"] = "complete"
        tasks[task_id]["progress"] = 100
        tasks[task_id]["message"] = "Videos generated successfully!"
        tasks[task_id]["result"] = {"output_dir": f"output/{video_set.set_id}/videos"}

    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["message"] = str(e)

# ============================================================================
# Startup
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)