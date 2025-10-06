"""
Unified Web API for Video Generation
====================================
FastAPI integration with the complete pipeline.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path

from video_gen.pipeline import get_pipeline, TaskStatus
from video_gen.shared.models import InputConfig


app = FastAPI(
    title="Video Generation API",
    description="Unified API for video generation from any source",
    version="1.0.0"
)


class CreateVideoRequest(BaseModel):
    """Request model for video creation."""
    input_type: str
    source: str
    voice: Optional[str] = "en-US-ChristopherNeural"
    language: Optional[str] = "en"
    color: Optional[str] = "blue"
    task_id: Optional[str] = None


class TaskStatusResponse(BaseModel):
    """Response model for task status."""
    task_id: str
    status: str
    current_stage: Optional[str] = None
    progress: Optional[float] = None
    video_path: Optional[str] = None
    errors: List[str] = []
    warnings: List[str] = []


@app.post("/api/create", response_model=dict)
async def create_video(request: CreateVideoRequest, background_tasks: BackgroundTasks):
    """
    Create video from source.

    Returns task_id immediately and processes in background.
    """
    try:
        # Create input config
        input_config = InputConfig(
            input_type=request.input_type,
            source=request.source,
            config={
                "voice": request.voice,
                "language": request.language,
                "color": request.color,
            }
        )

        # Get pipeline
        pipeline = get_pipeline()

        # Start async execution
        task_id = await pipeline.execute_async(input_config, request.task_id)

        return {
            "task_id": task_id,
            "status": "started",
            "message": "Video generation started"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/status/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """Get status of a video generation task."""
    pipeline = get_pipeline()
    task_state = pipeline.get_status(task_id)

    if not task_state:
        raise HTTPException(status_code=404, detail="Task not found")

    response = TaskStatusResponse(
        task_id=task_state.task_id,
        status=task_state.status.value,
        current_stage=task_state.current_stage,
        progress=task_state.overall_progress,
        errors=task_state.errors,
        warnings=task_state.warnings
    )

    # Add video path if completed
    if task_state.result and "video_path" in task_state.result:
        response.video_path = str(task_state.result["video_path"])

    return response


@app.get("/api/tasks")
async def list_tasks(status: Optional[str] = None, limit: int = 10):
    """List all tasks."""
    pipeline = get_pipeline()

    status_filter = None
    if status:
        try:
            status_filter = TaskStatus[status.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    tasks = pipeline.list_tasks(status_filter)
    tasks = tasks[:limit]

    return {
        "tasks": [
            {
                "task_id": task.task_id,
                "status": task.status.value,
                "current_stage": task.current_stage,
                "progress": task.overall_progress,
            }
            for task in tasks
        ]
    }


@app.delete("/api/cancel/{task_id}")
async def cancel_task(task_id: str):
    """Cancel a running task."""
    pipeline = get_pipeline()

    if pipeline.cancel(task_id):
        return {"message": f"Task {task_id} cancelled"}
    else:
        raise HTTPException(status_code=400, detail="Could not cancel task")


@app.get("/api/download/{task_id}")
async def download_video(task_id: str):
    """Download generated video."""
    pipeline = get_pipeline()
    task_state = pipeline.get_status(task_id)

    if not task_state:
        raise HTTPException(status_code=404, detail="Task not found")

    if task_state.status != TaskStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Video not ready yet")

    if not task_state.result or "video_path" not in task_state.result:
        raise HTTPException(status_code=404, detail="Video file not found")

    video_path = Path(task_state.result["video_path"])

    if not video_path.exists():
        raise HTTPException(status_code=404, detail="Video file not found")

    return FileResponse(
        path=video_path,
        media_type="video/mp4",
        filename=video_path.name
    )


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "video-generation"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
