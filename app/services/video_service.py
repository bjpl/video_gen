"""
Video Generation Service
========================
Service layer that integrates with existing video generation scripts
Manages job queue and coordinates video generation pipeline
"""

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
import uuid

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class JobStatus(Enum):
    """Job status enumeration"""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class VideoJob:
    """Video generation job"""
    job_id: str
    input_method: str
    status: JobStatus = JobStatus.QUEUED
    progress: int = 0
    message: str = ""
    created_at: datetime = field(default_factory=datetime.now)

    # Input parameters
    document_path: Optional[str] = None
    youtube_url: Optional[str] = None
    youtube_query: Optional[str] = None
    wizard_data: Optional[Dict[str, Any]] = None
    yaml_path: Optional[str] = None

    # Options
    accent_color: str = "blue"
    voice: str = "male"
    duration: int = 60
    use_ai: bool = False

    # Results
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class VideoGenerationService:
    """
    Service for managing video generation jobs

    Features:
    - In-memory job queue (can be replaced with Redis/DB)
    - Async job processing
    - Integration with existing scripts
    - Progress tracking
    """

    def __init__(self):
        self.jobs: Dict[str, VideoJob] = {}
        self.active_processes: Dict[str, subprocess.Popen] = {}

    def create_job(
        self,
        input_method: str,
        document_path: Optional[str] = None,
        youtube_url: Optional[str] = None,
        youtube_query: Optional[str] = None,
        wizard_data: Optional[Dict[str, Any]] = None,
        yaml_path: Optional[str] = None,
        accent_color: str = "blue",
        voice: str = "male",
        duration: int = 60,
        use_ai: bool = False
    ) -> VideoJob:
        """Create a new video generation job"""

        # Validate input method
        valid_methods = ["document", "youtube", "wizard", "yaml"]
        if input_method not in valid_methods:
            raise ValueError(f"Invalid input method. Must be one of: {valid_methods}")

        # Validate input parameters
        if input_method == "document" and not document_path:
            raise ValueError("document_path required for document input method")
        elif input_method == "youtube" and not (youtube_url or youtube_query):
            raise ValueError("youtube_url or youtube_query required for youtube input method")
        elif input_method == "wizard" and not wizard_data:
            raise ValueError("wizard_data required for wizard input method")
        elif input_method == "yaml" and not yaml_path:
            raise ValueError("yaml_path required for yaml input method")

        # Create job
        job = VideoJob(
            job_id=str(uuid.uuid4()),
            input_method=input_method,
            document_path=document_path,
            youtube_url=youtube_url,
            youtube_query=youtube_query,
            wizard_data=wizard_data,
            yaml_path=yaml_path,
            accent_color=accent_color,
            voice=voice,
            duration=duration,
            use_ai=use_ai
        )

        self.jobs[job.job_id] = job

        return job

    def get_job(self, job_id: str) -> Optional[VideoJob]:
        """Get job by ID"""
        return self.jobs.get(job_id)

    def list_jobs(self) -> List[VideoJob]:
        """List all jobs"""
        return list(self.jobs.values())

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        job = self.get_job(job_id)

        if not job or job.status in [JobStatus.COMPLETED, JobStatus.FAILED]:
            return False

        # Kill process if running
        if job_id in self.active_processes:
            try:
                self.active_processes[job_id].terminate()
                del self.active_processes[job_id]
            except:
                pass

        job.status = JobStatus.CANCELLED
        job.message = "Job cancelled by user"

        return True

    async def process_job(self, job_id: str):
        """
        Process a video generation job

        Pipeline:
        1. Generate YAML from input method
        2. Generate script (markdown + python)
        3. Generate audio (TTS)
        4. Generate video (rendering)
        """
        job = self.get_job(job_id)

        if not job:
            return

        try:
            job.status = JobStatus.PROCESSING
            job.progress = 0
            job.message = "Starting video generation..."

            # Step 1: Generate YAML (20% progress)
            yaml_file = await self._generate_yaml(job)
            job.progress = 20
            job.message = f"Generated YAML: {yaml_file}"

            # Step 2: Generate script (40% progress)
            await self._generate_script(job, yaml_file)
            job.progress = 40
            job.message = "Generated script files"

            # Step 3: Generate audio (70% progress)
            audio_files = await self._generate_audio(job)
            job.progress = 70
            job.message = f"Generated {len(audio_files)} audio files"

            # Step 4: Generate video (100% progress)
            video_files = await self._generate_video(job)
            job.progress = 100
            job.status = JobStatus.COMPLETED
            job.message = f"Successfully generated {len(video_files)} videos"

            job.result = {
                "yaml_file": yaml_file,
                "audio_files": audio_files,
                "video_files": video_files
            }

        except Exception as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            job.message = f"Generation failed: {str(e)}"

    async def _generate_yaml(self, job: VideoJob) -> str:
        """Generate YAML from input method"""

        # Build command based on input method
        cmd = [sys.executable, str(SCRIPTS_DIR / "create_video.py")]

        if job.input_method == "document":
            cmd.extend(["--document", job.document_path])
        elif job.input_method == "youtube":
            if job.youtube_url:
                cmd.extend(["--youtube-url", job.youtube_url])
            else:
                cmd.extend(["--youtube", job.youtube_query])
        elif job.input_method == "yaml":
            # YAML already exists, just return the path
            return job.yaml_path
        elif job.input_method == "wizard":
            # For wizard, we need to create YAML from wizard_data
            return await self._create_yaml_from_wizard(job)

        # Add common options
        cmd.extend([
            "--accent-color", job.accent_color,
            "--voice", job.voice,
            "--duration", str(job.duration)
        ])

        if job.use_ai:
            cmd.append("--use-ai")

        # Run command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise Exception(f"YAML generation failed: {stderr.decode()}")

        # Parse output to find YAML file path
        output = stdout.decode()

        # Look for YAML file in inputs directory
        inputs_dir = Path(__file__).parent.parent.parent / "inputs"
        yaml_files = sorted(inputs_dir.glob("*.yaml"), key=lambda x: x.stat().st_mtime)

        if not yaml_files:
            raise Exception("No YAML file generated")

        return str(yaml_files[-1])  # Return most recent YAML

    async def _create_yaml_from_wizard(self, job: VideoJob) -> str:
        """Create YAML file from wizard data"""
        import yaml

        # Build YAML structure from wizard data
        yaml_data = {
            "video": {
                "title": job.wizard_data.get("title", "Untitled Video"),
                "accent_color": job.accent_color
            },
            "scenes": []
        }

        # Add scenes from wizard data
        for scene in job.wizard_data.get("scenes", []):
            yaml_data["scenes"].append(scene)

        # Save YAML file
        inputs_dir = Path(__file__).parent.parent.parent / "inputs"
        inputs_dir.mkdir(exist_ok=True)

        yaml_file = inputs_dir / f"wizard_{job.job_id[:8]}.yaml"

        with open(yaml_file, "w") as f:
            yaml.dump(yaml_data, f, default_flow_style=False)

        return str(yaml_file)

    async def _generate_script(self, job: VideoJob, yaml_file: str):
        """Generate script files from YAML"""

        # For now, this is handled by the audio generation step
        # Scripts are generated as part of generate_all_videos_unified_v2.py

    async def _generate_audio(self, job: VideoJob) -> List[str]:
        """Generate audio files from scripts"""

        # Change to scripts directory
        scripts_dir = Path(__file__).parent.parent.parent / "scripts"

        # Run audio generation
        cmd = [
            sys.executable,
            str(scripts_dir / "generate_all_videos_unified_v2.py")
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(scripts_dir)
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise Exception(f"Audio generation failed: {stderr.decode()}")

        # Find generated audio files
        audio_dir = Path(__file__).parent.parent.parent / "audio"
        audio_files = list(audio_dir.glob("*.mp3"))

        return [str(f) for f in audio_files]

    async def _generate_video(self, job: VideoJob) -> List[str]:
        """Generate video files from audio"""

        # Change to scripts directory
        scripts_dir = Path(__file__).parent.parent.parent / "scripts"

        # Run video generation
        cmd = [
            sys.executable,
            str(scripts_dir / "generate_videos_from_timings_v3_simple.py")
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(scripts_dir)
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise Exception(f"Video generation failed: {stderr.decode()}")

        # Find generated video files
        videos_dir = Path(__file__).parent.parent.parent / "videos"
        video_files = list(videos_dir.glob("*.mp4"))

        return [str(f) for f in video_files]
