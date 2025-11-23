"""
Test Data and Fixtures
======================

Comprehensive test data for integration and E2E testing including:
- Sample documents (markdown, txt, rst)
- Sample YouTube URLs
- Mock API responses
- Test language configurations
- Test voice configurations
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json

# ============================================================================
# Sample Documents
# ============================================================================

SAMPLE_DOCUMENTS = {
    "markdown_simple": {
        "filename": "simple_guide.md",
        "content": """# Introduction to Python

## What is Python?

Python is a high-level, interpreted programming language known for its simplicity.

- Easy to learn
- Readable syntax
- Large community

## Getting Started

To install Python, visit python.org and download the latest version.

```bash
python --version
```

## Your First Program

Create a file called `hello.py`:

```python
print("Hello, World!")
```

## Conclusion

Python is a great language for beginners and experts alike.
""",
        "expected_sections": 4,
        "expected_scenes": 6,
        "format": "markdown"
    },

    "markdown_complex": {
        "filename": "advanced_tutorial.md",
        "content": """# Advanced Python Patterns

## Design Patterns

### Singleton Pattern

The Singleton pattern ensures a class has only one instance.

```python
class Singleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
```

### Factory Pattern

Factory pattern provides an interface for creating objects.

- Decouples creation from usage
- Enables dependency injection
- Simplifies testing

## Performance Tips

1. Use generators for large datasets
2. Profile before optimizing
3. Consider using NumPy for numerical operations

## Best Practices

> "Code is read more often than it is written." - Guido van Rossum

### Key Principles

- Write readable code
- Follow PEP 8 guidelines
- Document your functions

## Summary

Design patterns and best practices lead to maintainable code.
""",
        "expected_sections": 5,
        "expected_scenes": 12,
        "format": "markdown"
    },

    "plain_text": {
        "filename": "notes.txt",
        "content": """Introduction to Web Development

Web development involves creating websites and web applications.

Frontend Development
HTML provides the structure of web pages.
CSS adds styling and visual design.
JavaScript adds interactivity.

Backend Development
Server-side programming handles business logic.
Databases store and manage data.
APIs enable communication between services.

Getting Started
1. Learn HTML basics
2. Add CSS for styling
3. Introduce JavaScript
4. Build a simple project

Resources
Visit MDN Web Docs for comprehensive guides.
Practice on CodePen or similar platforms.
""",
        "expected_sections": 4,
        "expected_scenes": 8,
        "format": "plain_text"
    },

    "restructured_text": {
        "filename": "documentation.rst",
        "content": """======================
Python Documentation
======================

Introduction
============

This is a guide to Python programming.

Features
--------

* Dynamic typing
* Automatic memory management
* Extensive standard library

Installation
============

Download from python.org::

    wget https://python.org/downloads/python-3.11.tar.gz
    tar -xzf python-3.11.tar.gz
    ./configure && make && make install

Basic Syntax
============

Variables
---------

Python uses dynamic typing::

    name = "John"
    age = 25
    is_active = True

Functions
---------

Define functions with def::

    def greet(name):
        return f"Hello, {name}!"

Conclusion
==========

Python is versatile and powerful.
""",
        "expected_sections": 4,
        "expected_scenes": 8,
        "format": "rst"
    },

    "empty_document": {
        "filename": "empty.md",
        "content": "",
        "expected_sections": 0,
        "expected_scenes": 0,
        "format": "markdown",
        "should_fail_validation": True
    },

    "minimal_document": {
        "filename": "minimal.md",
        "content": "# Title\n\nSome content.",
        "expected_sections": 1,
        "expected_scenes": 1,
        "format": "markdown"
    },

    "large_document": {
        "filename": "large_guide.md",
        "content": None,  # Generated dynamically
        "expected_sections": 20,
        "expected_scenes": 50,
        "format": "markdown"
    }
}


def generate_large_document(sections: int = 20) -> str:
    """Generate a large document for performance testing."""
    content = "# Comprehensive Programming Guide\n\n"

    for i in range(1, sections + 1):
        content += f"\n## Chapter {i}: Topic {i}\n\n"
        content += f"This chapter covers important concepts about topic {i}.\n\n"
        content += "### Key Points\n\n"
        content += "- First important point\n"
        content += "- Second important point\n"
        content += "- Third important point\n\n"
        content += "### Code Example\n\n"
        content += f"```python\ndef function_{i}():\n    return 'Result {i}'\n```\n\n"
        content += f"This concludes chapter {i}.\n"

    return content


# Initialize large document content
SAMPLE_DOCUMENTS["large_document"]["content"] = generate_large_document(20)


# ============================================================================
# Sample YouTube URLs
# ============================================================================

SAMPLE_YOUTUBE_URLS = {
    "valid_standard": {
        "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "video_id": "dQw4w9WgXcQ",
        "is_valid": True
    },
    "valid_short": {
        "url": "https://youtu.be/dQw4w9WgXcQ",
        "video_id": "dQw4w9WgXcQ",
        "is_valid": True
    },
    "valid_embed": {
        "url": "https://www.youtube.com/embed/dQw4w9WgXcQ",
        "video_id": "dQw4w9WgXcQ",
        "is_valid": True
    },
    "valid_without_www": {
        "url": "https://youtube.com/watch?v=dQw4w9WgXcQ",
        "video_id": "dQw4w9WgXcQ",
        "is_valid": True
    },
    "valid_with_params": {
        "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=30",
        "video_id": "dQw4w9WgXcQ",
        "is_valid": True
    },
    "invalid_empty": {
        "url": "",
        "video_id": None,
        "is_valid": False,
        "error": "URL cannot be empty"
    },
    "invalid_not_url": {
        "url": "not-a-valid-url",
        "video_id": None,
        "is_valid": False,
        "error": "Invalid URL format"
    },
    "invalid_vimeo": {
        "url": "https://vimeo.com/123456789",
        "video_id": None,
        "is_valid": False,
        "error": "Not a YouTube URL"
    },
    "invalid_channel": {
        "url": "https://www.youtube.com/channel/UC1234567890",
        "video_id": None,
        "is_valid": False,
        "error": "Not a video URL"
    },
    "invalid_playlist": {
        "url": "https://www.youtube.com/playlist?list=PLxyz",
        "video_id": None,
        "is_valid": False,
        "error": "Not a video URL"
    },
    "invalid_malformed_id": {
        "url": "https://www.youtube.com/watch?v=abc",
        "video_id": None,
        "is_valid": False,
        "error": "Invalid video ID"
    }
}


# ============================================================================
# Mock API Responses
# ============================================================================

MOCK_API_RESPONSES = {
    "validation_success": {
        "valid": True,
        "sanitized_filename": "document.md",
        "errors": [],
        "warnings": [],
        "preview": {
            "title": "Test Document",
            "section_count": 4,
            "word_count": 250,
            "estimated_duration": "2:30",
            "estimated_scenes": 6
        }
    },

    "validation_failure_file_type": {
        "valid": False,
        "errors": ["Unsupported file type. Allowed: .md, .txt, .rst"],
        "warnings": []
    },

    "validation_failure_file_size": {
        "valid": False,
        "errors": ["File size exceeds maximum allowed (10MB)"],
        "warnings": []
    },

    "validation_failure_empty": {
        "valid": False,
        "errors": ["File is empty"],
        "warnings": []
    },

    "preview_success": {
        "status": "success",
        "preview": {
            "title": "Python Tutorial",
            "sections": ["Introduction", "Getting Started", "Advanced Topics", "Conclusion"],
            "section_count": 4,
            "word_count": 350,
            "has_code": True,
            "has_lists": True,
            "estimated_duration": "3:15",
            "estimated_scenes": 8,
            "format": "markdown"
        },
        "ready_for_generation": True,
        "recommendations": ["Document looks good for video generation!"]
    },

    "youtube_validation_success": {
        "is_valid": True,
        "video_id": "dQw4w9WgXcQ",
        "normalized_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "error": None
    },

    "youtube_preview_success": {
        "status": "success",
        "video_id": "dQw4w9WgXcQ",
        "preview": {
            "title": "Sample Video Title",
            "channel": "Sample Channel",
            "duration_seconds": 180,
            "duration_formatted": "3:00",
            "thumbnail": "https://img.youtube.com/vi/dQw4w9WgXcQ/maxresdefault.jpg",
            "has_transcript": True,
            "transcript_languages": ["en", "es", "fr"],
            "estimated_scenes": 8,
            "estimated_generation_time": "2-3 minutes"
        }
    },

    "progress_parsing": {
        "task_id": "task_123",
        "status": "processing",
        "progress": 15,
        "stage": "parsing",
        "message": "Parsing document content..."
    },

    "progress_generating": {
        "task_id": "task_123",
        "status": "processing",
        "progress": 45,
        "stage": "generating",
        "message": "Generating video scenes..."
    },

    "progress_rendering": {
        "task_id": "task_123",
        "status": "processing",
        "progress": 75,
        "stage": "rendering",
        "message": "Rendering video..."
    },

    "progress_complete": {
        "task_id": "task_123",
        "status": "complete",
        "progress": 100,
        "stage": "complete",
        "message": "Video generation complete!",
        "result": {
            "video_url": "/output/task_123/video.mp4",
            "thumbnail_url": "/output/task_123/thumbnail.jpg"
        }
    },

    "progress_failed": {
        "task_id": "task_123",
        "status": "failed",
        "progress": 45,
        "stage": "generating",
        "message": "Generation failed",
        "error": "Internal processing error"
    }
}


# ============================================================================
# Test Language Configurations
# ============================================================================

TEST_LANGUAGE_CONFIGS = {
    "single_english": {
        "languages": ["en"],
        "expected_videos": 1
    },
    "bilingual": {
        "languages": ["en", "es"],
        "expected_videos": 2
    },
    "trilingual": {
        "languages": ["en", "es", "fr"],
        "expected_videos": 3
    },
    "five_languages": {
        "languages": ["en", "es", "fr", "de", "ja"],
        "expected_videos": 5
    },
    "rtl_language": {
        "languages": ["en", "ar"],
        "expected_videos": 2,
        "includes_rtl": True
    },
    "asian_languages": {
        "languages": ["zh", "ja", "ko"],
        "expected_videos": 3
    },
    "european_mix": {
        "languages": ["en", "de", "fr", "it", "pt"],
        "expected_videos": 5
    }
}


# ============================================================================
# Test Voice Configurations
# ============================================================================

TEST_VOICE_CONFIGS = {
    "english_voices": {
        "language": "en",
        "voices": ["male", "female", "male_warm", "female_friendly"],
        "default": "male"
    },
    "spanish_voices": {
        "language": "es",
        "voices": ["male_es", "female_es"],
        "default": "male_es"
    },
    "french_voices": {
        "language": "fr",
        "voices": ["male_fr", "female_fr"],
        "default": "male_fr"
    },
    "german_voices": {
        "language": "de",
        "voices": ["male_de", "female_de"],
        "default": "male_de"
    },
    "japanese_voices": {
        "language": "ja",
        "voices": ["male_ja", "female_ja"],
        "default": "male_ja"
    },
    "multi_voice_set": {
        "en": ["male", "female"],
        "es": ["male_es"],
        "fr": ["female_fr"]
    }
}


# ============================================================================
# Helper Functions
# ============================================================================

def get_sample_document(doc_type: str = "markdown_simple") -> Dict[str, Any]:
    """
    Get a sample document for testing.

    Args:
        doc_type: Type of document (markdown_simple, markdown_complex, etc.)

    Returns:
        Document data dictionary
    """
    if doc_type not in SAMPLE_DOCUMENTS:
        raise ValueError(f"Unknown document type: {doc_type}")
    return SAMPLE_DOCUMENTS[doc_type].copy()


def get_mock_validation_response(success: bool = True, **overrides) -> Dict[str, Any]:
    """
    Get a mock validation API response.

    Args:
        success: Whether validation should succeed
        **overrides: Fields to override in the response

    Returns:
        Mock API response dictionary
    """
    if success:
        response = MOCK_API_RESPONSES["validation_success"].copy()
    else:
        response = MOCK_API_RESPONSES["validation_failure_file_type"].copy()

    response.update(overrides)
    return response


def get_mock_preview_response(**overrides) -> Dict[str, Any]:
    """
    Get a mock preview API response.

    Args:
        **overrides: Fields to override in the response

    Returns:
        Mock API response dictionary
    """
    response = MOCK_API_RESPONSES["preview_success"].copy()
    response.update(overrides)
    return response


def get_mock_progress_response(
    stage: str = "parsing",
    progress: int = 0,
    task_id: str = "task_123"
) -> Dict[str, Any]:
    """
    Get a mock progress API response.

    Args:
        stage: Current stage (parsing, generating, rendering, complete)
        progress: Progress percentage
        task_id: Task identifier

    Returns:
        Mock API response dictionary
    """
    stage_map = {
        "parsing": MOCK_API_RESPONSES["progress_parsing"],
        "generating": MOCK_API_RESPONSES["progress_generating"],
        "rendering": MOCK_API_RESPONSES["progress_rendering"],
        "complete": MOCK_API_RESPONSES["progress_complete"],
        "failed": MOCK_API_RESPONSES["progress_failed"]
    }

    response = stage_map.get(stage, MOCK_API_RESPONSES["progress_parsing"]).copy()
    response["task_id"] = task_id
    if progress > 0:
        response["progress"] = progress

    return response


def create_test_file_bytes(
    content: str,
    encoding: str = "utf-8"
) -> bytes:
    """
    Create file bytes for upload testing.

    Args:
        content: File content as string
        encoding: Character encoding

    Returns:
        Content as bytes
    """
    return content.encode(encoding)


def generate_invalid_file_content(file_type: str) -> bytes:
    """
    Generate invalid file content for error testing.

    Args:
        file_type: Type of invalid content to generate

    Returns:
        Invalid file bytes
    """
    if file_type == "binary":
        # Random binary content
        return bytes([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD] * 100)
    elif file_type == "null_bytes":
        return b"Content with \x00 null \x00 bytes"
    elif file_type == "oversized":
        # 15MB of content (exceeds 10MB limit)
        return b"x" * (15 * 1024 * 1024)
    else:
        return b""


# ============================================================================
# Test Data Generators
# ============================================================================

def generate_test_video_set(
    num_videos: int = 3,
    scenes_per_video: int = 5,
    languages: List[str] = None
) -> Dict[str, Any]:
    """
    Generate a test video set configuration.

    Args:
        num_videos: Number of videos in the set
        scenes_per_video: Number of scenes per video
        languages: Target languages

    Returns:
        Video set configuration dictionary
    """
    if languages is None:
        languages = ["en"]

    videos = []
    for i in range(num_videos):
        scenes = []
        scenes.append({
            "type": "title",
            "title": f"Video {i + 1}",
            "subtitle": f"Generated Test Video",
            "narration": f"Welcome to video {i + 1}"
        })

        for j in range(scenes_per_video - 2):
            scenes.append({
                "type": "list",
                "title": f"Section {j + 1}",
                "items": [f"Point {k + 1}" for k in range(3)],
                "narration": f"Here are the key points for section {j + 1}"
            })

        scenes.append({
            "type": "outro",
            "message": "Thanks for watching!",
            "cta": "Subscribe for more",
            "narration": "Thank you for watching this video."
        })

        videos.append({
            "video_id": f"test_video_{i + 1}",
            "title": f"Test Video {i + 1}",
            "scenes": scenes,
            "voice": "male"
        })

    return {
        "set_id": f"test_set_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "set_name": "Test Video Set",
        "videos": videos,
        "accent_color": "blue",
        "languages": languages
    }


def generate_test_generation_config(
    input_type: str = "document",
    languages: List[str] = None,
    voice: str = "male"
) -> Dict[str, Any]:
    """
    Generate a test generation configuration.

    Args:
        input_type: Type of input (document, youtube)
        languages: Target languages
        voice: Voice selection

    Returns:
        Generation configuration dictionary
    """
    if languages is None:
        languages = ["en"]

    config = {
        "input_type": input_type,
        "accent_color": "blue",
        "voice": voice,
        "languages": languages
    }

    if input_type == "document":
        config["source"] = "/path/to/document.md"
        config["video_count"] = 1
    elif input_type == "youtube":
        config["source"] = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    return config
