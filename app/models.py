"""
Pydantic Models for Video Generation API
=========================================
Type-safe data models for FastAPI endpoints.
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, HttpUrl


# Input Models

class ParseRequest(BaseModel):
    """Request to parse input content"""
    input_type: Literal["document", "youtube", "wizard"]

    # Document input
    document_path: Optional[str] = None
    document_url: Optional[HttpUrl] = None

    # YouTube input
    youtube_url: Optional[HttpUrl] = None
    youtube_id: Optional[str] = None
    youtube_query: Optional[str] = None

    # Wizard input
    wizard_data: Optional[Dict[str, Any]] = None

    # Common options
    accent_color: str = Field(default="blue", pattern="^(orange|blue|purple|green|pink|cyan)$")
    voice: str = Field(default="male", pattern="^(male|female|male_warm|female_friendly)$")
    duration: int = Field(default=60, ge=10, le=600)
    use_ai: bool = Field(default=False, description="Use Claude AI for narration")

    class Config:
        json_schema_extra = {
            "example": {
                "input_type": "document",
                "document_path": "README.md",
                "accent_color": "blue",
                "voice": "male",
                "duration": 60
            }
        }


class ParseResponse(BaseModel):
    """Response from parsing input"""
    job_id: str
    status: str
    message: str
    scenes: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}


class GenerateRequest(BaseModel):
    """Request to generate video from scenes"""
    scenes: List[Dict[str, Any]]
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Video configuration (accent_color, voice, etc.)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "scenes": [
                    {
                        "type": "title",
                        "title": "Getting Started",
                        "subtitle": "A Quick Introduction",
                        "voice": "male"
                    },
                    {
                        "type": "command",
                        "command_name": "Installation",
                        "description": "Install dependencies",
                        "commands": ["pip install -r requirements.txt"],
                        "voice": "male"
                    }
                ],
                "config": {
                    "accent_color": "blue",
                    "default_voice": "male"
                }
            }
        }


class GenerateResponse(BaseModel):
    """Response from video generation request"""
    job_id: str
    status: str
    message: str
    estimated_time_seconds: int


# Status Models

class JobStatus(BaseModel):
    """Current status of a video generation job"""
    job_id: str
    status: Literal["queued", "parsing", "generating", "completed", "error"]
    progress: int = Field(ge=0, le=100)
    message: str = ""
    created_at: str
    output_path: Optional[str] = None
    error: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "job_id": "abc123",
                "status": "generating",
                "progress": 45,
                "message": "Generating scene 3 of 5",
                "created_at": "2025-10-04T12:00:00Z"
            }
        }


# Template Models

class InputMethod(BaseModel):
    """Available input method"""
    id: str
    name: str
    description: str
    icon: str
    time_estimate: str


class Template(BaseModel):
    """Example template"""
    id: str
    name: str
    description: str
    category: str
    scene_types: List[str]
    estimated_duration: int
    example_path: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "id": "simple_tutorial",
                "name": "Simple Tutorial",
                "description": "Basic tutorial template with title, commands, and outro",
                "category": "tutorial",
                "scene_types": ["title", "command", "outro"],
                "estimated_duration": 60,
                "example_path": "inputs/example_simple.yaml"
            }
        }


# Scene Models (for validation)

class BaseScene(BaseModel):
    """Base scene structure"""
    type: str
    voice: Optional[str] = "male"
    narration: Optional[str] = None


class TitleScene(BaseScene):
    """Title scene"""
    type: Literal["title"] = "title"
    title: str
    subtitle: str


class CommandScene(BaseScene):
    """Command scene"""
    type: Literal["command"] = "command"
    command_name: str
    description: str
    commands: List[str]


class ListScene(BaseScene):
    """List scene"""
    type: Literal["list"] = "list"
    title: str
    items: List[str]


class OutroScene(BaseScene):
    """Outro scene"""
    type: Literal["outro"] = "outro"
    title: str
    subtitle: str


class CodeComparisonScene(BaseScene):
    """Code comparison scene"""
    type: Literal["code_comparison"] = "code_comparison"
    title: str
    before_label: str
    after_label: str
    before_code: List[str]
    after_code: List[str]


class QuoteScene(BaseScene):
    """Quote scene"""
    type: Literal["quote"] = "quote"
    quote: str
    attribution: str


# Educational scene types

class LearningObjectivesScene(BaseScene):
    """Learning objectives scene"""
    type: Literal["learning_objectives"] = "learning_objectives"
    title: str
    objectives: List[str]


class ProblemScene(BaseScene):
    """Problem presentation scene"""
    type: Literal["problem"] = "problem"
    title: str
    description: str
    constraints: Optional[List[str]] = None


class SolutionScene(BaseScene):
    """Solution scene"""
    type: Literal["solution"] = "solution"
    title: str
    explanation: str
    code: List[str]


class CheckpointScene(BaseScene):
    """Checkpoint scene"""
    type: Literal["checkpoint"] = "checkpoint"
    title: str
    key_points: List[str]


class QuizScene(BaseScene):
    """Quiz scene"""
    type: Literal["quiz"] = "quiz"
    question: str
    options: List[str]
    correct_answer: int


class ExerciseScene(BaseScene):
    """Exercise scene"""
    type: Literal["exercise"] = "exercise"
    title: str
    instructions: str
    hints: Optional[List[str]] = None


# Video Configuration

class VideoConfig(BaseModel):
    """Video generation configuration"""
    accent_color: str = Field(default="blue", pattern="^(orange|blue|purple|green|pink|cyan)$")
    default_voice: str = Field(default="male", pattern="^(male|female|male_warm|female_friendly)$")
    resolution: str = Field(default="1920x1080", pattern="^\\d+x\\d+$")
    fps: int = Field(default=30, ge=24, le=60)
    use_ai_narration: bool = False
    output_format: str = Field(default="mp4", pattern="^(mp4|webm|mov)$")

    class Config:
        json_schema_extra = {
            "example": {
                "accent_color": "blue",
                "default_voice": "male",
                "resolution": "1920x1080",
                "fps": 30,
                "use_ai_narration": False,
                "output_format": "mp4"
            }
        }
