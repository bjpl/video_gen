"""
Utility Functions for Video Generation API
===========================================
Helper functions to integrate with existing scripts.
"""

import sys
import asyncio
from pathlib import Path
from typing import Dict, Any, List
import yaml

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# Import existing functionality
try:
    from generate_script_from_document import MarkdownParser, read_document
    from youtube_to_programmatic import extract_video_id, fetch_transcript
except ImportError as e:
    print(f"Warning: Could not import scripts: {e}")


# ============================================================================
# Input Methods
# ============================================================================

async def get_input_methods() -> List[Dict[str, str]]:
    """Get list of available input methods"""
    return [
        {
            "id": "document",
            "name": "Document",
            "description": "Parse README, guides, markdown",
            "icon": "📄"
        },
        {
            "id": "youtube",
            "name": "YouTube",
            "description": "Fetch transcripts, create summaries",
            "icon": "📺"
        },
        {
            "id": "wizard",
            "name": "Wizard",
            "description": "Interactive guided creation",
            "icon": "🧙"
        }
    ]


# ============================================================================
# Parsing Functions
# ============================================================================

async def parse_document_input(request, job_id: str) -> Dict[str, Any]:
    """
    Parse document input (markdown, README, etc.)
    Uses existing generate_script_from_document.py
    """
    try:
        # Get document source
        source = request.document_path or request.document_url
        if not source:
            raise ValueError("No document source provided")

        # Read document
        content = read_document(source)

        # Parse structure
        parser = MarkdownParser()
        structure = parser.parse(content)

        # Convert to scenes
        scenes = _convert_structure_to_scenes(structure)

        return {
            "scenes": scenes,
            "metadata": {
                "source": source,
                "title": structure.get("title", "Untitled"),
                "scene_count": len(scenes)
            }
        }

    except Exception as e:
        raise Exception(f"Document parsing failed: {str(e)}")


async def parse_youtube_input(request, job_id: str) -> Dict[str, Any]:
    """
    Parse YouTube input (URL or search query)
    Uses existing youtube_to_programmatic.py
    """
    try:
        # Get video ID
        if request.youtube_url:
            video_id = extract_video_id(str(request.youtube_url))
        elif request.youtube_id:
            video_id = request.youtube_id
        else:
            # TODO: Implement YouTube search
            raise ValueError("YouTube search not yet implemented")

        if not video_id:
            raise ValueError("Could not extract video ID")

        # Fetch transcript
        transcript_data = fetch_transcript(video_id)
        if not transcript_data:
            raise ValueError("Could not fetch transcript")

        # Parse into scenes
        scenes = _convert_transcript_to_scenes(
            transcript_data,
            target_duration=request.duration
        )

        return {
            "scenes": scenes,
            "metadata": {
                "video_id": video_id,
                "transcript_length": len(transcript_data.get("transcript", "")),
                "scene_count": len(scenes)
            }
        }

    except Exception as e:
        raise Exception(f"YouTube parsing failed: {str(e)}")


async def parse_wizard_input(request, job_id: str) -> Dict[str, Any]:
    """
    Parse wizard input (interactive Q&A)
    Uses wizard_data from request
    """
    try:
        wizard_data = request.wizard_data
        if not wizard_data:
            raise ValueError("No wizard data provided")

        # Convert wizard data to scenes
        scenes = _convert_wizard_to_scenes(wizard_data)

        return {
            "scenes": scenes,
            "metadata": {
                "source": "wizard",
                "scene_count": len(scenes)
            }
        }

    except Exception as e:
        raise Exception(f"Wizard parsing failed: {str(e)}")


# ============================================================================
# Video Generation
# ============================================================================

async def trigger_video_generation(
    job_id: str,
    scenes: List[Dict],
    config: Dict,
    job_store: Dict
):
    """
    Trigger video generation in background.
    Updates job_store with progress.

    Process:
    1. Create YAML from scenes
    2. Generate audio (scripts/generate_all_videos_unified_v2.py)
    3. Generate video (scripts/generate_videos_from_timings_v3_simple.py)
    """
    try:
        # Update status
        job_store[job_id]["status"] = "generating"
        job_store[job_id]["progress"] = 10
        job_store[job_id]["message"] = "Creating video specification..."

        # Create YAML file
        yaml_path = await _create_yaml_from_scenes(job_id, scenes, config)

        job_store[job_id]["progress"] = 20
        job_store[job_id]["message"] = "Generating audio narration..."

        # Generate audio
        await _generate_audio(yaml_path, job_store, job_id)

        job_store[job_id]["progress"] = 60
        job_store[job_id]["message"] = "Rendering video..."

        # Generate video
        output_path = await _generate_video(yaml_path, job_store, job_id)

        # Complete
        job_store[job_id]["status"] = "completed"
        job_store[job_id]["progress"] = 100
        job_store[job_id]["message"] = "Video generation complete!"
        job_store[job_id]["output_path"] = str(output_path)
        job_store[job_id]["video_file"] = output_path.name

    except Exception as e:
        job_store[job_id]["status"] = "error"
        job_store[job_id]["error"] = str(e)
        job_store[job_id]["message"] = f"Generation failed: {str(e)}"


async def get_job_status(job_id: str, job_store: Dict) -> Dict:
    """Get current status of a job"""
    if job_id not in job_store:
        raise ValueError(f"Job {job_id} not found")

    return job_store[job_id]


# ============================================================================
# Templates
# ============================================================================

async def list_templates() -> List[Dict]:
    """List available example templates"""
    templates_dir = Path(__file__).parent.parent / "inputs"

    templates = []

    # Scan for example YAML files
    for yaml_file in templates_dir.glob("example_*.yaml"):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)

            templates.append({
                "id": yaml_file.stem,
                "name": yaml_file.stem.replace("_", " ").title(),
                "description": f"Example template from {yaml_file.name}",
                "category": "example",
                "scene_types": _extract_scene_types(data),
                "estimated_duration": 60,
                "example_path": str(yaml_file)
            })
        except Exception as e:
            print(f"Warning: Could not load {yaml_file}: {e}")

    return templates


# ============================================================================
# Helper Functions
# ============================================================================

def _convert_structure_to_scenes(structure: Dict) -> List[Dict]:
    """Convert parsed markdown structure to scenes"""
    scenes = []

    # Title scene
    if structure.get("title"):
        scenes.append({
            "type": "title",
            "title": structure["title"],
            "subtitle": structure.get("subtitle", "")
        })

    # Convert sections to scenes
    for section in structure.get("sections", []):
        if section.get("type") == "code":
            scenes.append({
                "type": "command",
                "command_name": section.get("title", "Code Example"),
                "description": section.get("description", ""),
                "commands": section.get("code_lines", [])
            })
        elif section.get("type") == "list":
            scenes.append({
                "type": "list",
                "title": section.get("title", "Key Points"),
                "items": section.get("items", [])
            })
        else:
            # Default to text content
            continue

    # Outro
    scenes.append({
        "type": "outro",
        "title": "Thanks for watching!",
        "subtitle": "Subscribe for more content"
    })

    return scenes


def _convert_transcript_to_scenes(transcript_data: Dict, target_duration: int) -> List[Dict]:
    """Convert YouTube transcript to scenes"""
    # Simplified: Create title + summary scenes
    # In production, use AI to segment transcript

    text = transcript_data.get("transcript", "")

    # Split into chunks (rough segmentation)
    chunk_size = len(text) // 3
    chunks = [
        text[i:i+chunk_size]
        for i in range(0, len(text), chunk_size)
    ][:3]

    scenes = [
        {
            "type": "title",
            "title": "Video Summary",
            "subtitle": "Key Highlights"
        }
    ]

    for i, chunk in enumerate(chunks, 1):
        scenes.append({
            "type": "list",
            "title": f"Part {i}",
            "items": [chunk[:200] + "..."]  # Truncate for brevity
        })

    scenes.append({
        "type": "outro",
        "title": "Summary Complete",
        "subtitle": "Watch the full video for details"
    })

    return scenes


def _convert_wizard_to_scenes(wizard_data: Dict) -> List[Dict]:
    """Convert wizard input to scenes"""
    # Extract scenes from wizard data structure
    return wizard_data.get("scenes", [])


def _extract_scene_types(yaml_data: Dict) -> List[str]:
    """Extract scene types from YAML data"""
    scenes = yaml_data.get("video", {}).get("scenes", [])
    return list(set(scene.get("type", "unknown") for scene in scenes))


async def _create_yaml_from_scenes(
    job_id: str,
    scenes: List[Dict],
    config: Dict
) -> Path:
    """Create YAML file from scenes"""
    inputs_dir = Path(__file__).parent.parent / "inputs"
    inputs_dir.mkdir(exist_ok=True)

    yaml_path = inputs_dir / f"web_ui_{job_id}.yaml"

    yaml_data = {
        "video": {
            "id": f"web_ui_{job_id}",
            "title": f"Video {job_id}",
            "accent_color": config.get("accent_color", "blue"),
            "scenes": scenes
        }
    }

    with open(yaml_path, "w") as f:
        yaml.dump(yaml_data, f, default_flow_style=False)

    return yaml_path


async def _generate_audio(yaml_path: Path, job_store: Dict, job_id: str):
    """Generate audio using existing scripts"""
    cmd = [
        sys.executable,
        str(SCRIPTS_DIR / "generate_all_videos_unified_v2.py")
    ]

    # Run in subprocess
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(SCRIPTS_DIR)
    )

    stdout, stderr = await process.wait()

    if process.returncode != 0:
        raise Exception(f"Audio generation failed: {stderr.decode()}")

    job_store[job_id]["audio_output"] = stdout.decode()


async def _generate_video(yaml_path: Path, job_store: Dict, job_id: str) -> Path:
    """Generate video using existing scripts"""
    cmd = [
        sys.executable,
        str(SCRIPTS_DIR / "generate_videos_from_timings_v3_simple.py")
    ]

    # Run in subprocess
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(SCRIPTS_DIR)
    )

    stdout, stderr = await process.wait()

    if process.returncode != 0:
        raise Exception(f"Video generation failed: {stderr.decode()}")

    job_store[job_id]["video_output"] = stdout.decode()

    # Find generated video
    output_dir = Path(__file__).parent.parent / "output"
    video_files = list(output_dir.glob(f"*{job_id}*.mp4"))

    if not video_files:
        raise Exception("Generated video not found")

    return video_files[0]
