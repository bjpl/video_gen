"""
Document Parsing Routes

Endpoints for document upload, validation, preview, and parsing.
"""
import logging
import time
import secrets
from pathlib import Path
from typing import Dict, List
from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse

from app.models.requests import DocumentInput
from video_gen.shared.models import InputConfig
from video_gen.pipeline import get_pipeline

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
        convert_to_markdown,
        is_binary_content,
    )
except ImportError:
    pass

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["documents"])


@router.post("/parse/document")
async def parse_document(input: DocumentInput, background_tasks: BackgroundTasks):
    """
    Parse document and generate video set.
    Now uses unified pipeline for consistency.
    """
    try:
        from app.services.pipeline import execute_pipeline_task

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
            split_strategy=input.split_strategy,  # NEW: Intelligent splitting strategy
            split_by_h2=(input.split_by_h2 if input.split_by_h2 is not None else (input.video_count > 1)),  # Legacy support
            enable_ai_splitting=input.enable_ai_splitting  # NEW: AI toggle
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


@router.post("/upload/document")
async def upload_document(
    file: UploadFile = File(...),
    accent_color: str = Form("blue"),
    voice: str = Form("male"),
    video_count: int = Form(1),
    background_tasks: BackgroundTasks = None
):
    """
    Upload a document file and generate video set.
    Accepts multipart/form-data with file upload.
    """
    try:
        from app.services.pipeline import execute_pipeline_task

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

        # Generate task ID with millisecond precision and random suffix for uniqueness
        task_id = f"upload_{int(time.time() * 1000)}_{secrets.token_hex(4)}"

        # Create uploads directory if it doesn't exist
        uploads_dir = Path(__file__).parent.parent.parent / "uploads"
        uploads_dir.mkdir(exist_ok=True)

        # Sanitize filename using comprehensive validation
        sanitized_filename = sanitize_filename(file.filename)
        # Additional removal of unicode control characters (RTLO, etc.)
        sanitized_filename = ''.join(c for c in sanitized_filename if ord(c) < 0x202A or ord(c) > 0x202E)
        # Remove null bytes
        sanitized_filename = sanitized_filename.replace('\x00', '')
        upload_path = uploads_dir / f"{task_id}_{sanitized_filename}"

        with open(upload_path, "wb") as f:
            f.write(content)

        logger.info(f"File uploaded: {upload_path} ({len(content)} bytes)")

        # CRITICAL: Convert Path to absolute string and ensure it's normalized
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


@router.post("/validate/document")
async def validate_document_upload(file: UploadFile = File(...)):
    """
    Validate a document file before processing.

    Performs real-time validation including:
    - File extension check
    - File size validation
    - Content type verification
    - Binary content detection
    - Document structure preview

    Returns validation result with preview data for UI display.
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


@router.post("/preview/document")
async def preview_document(file: UploadFile = File(...)):
    """
    Generate a detailed preview of document structure.

    Returns:
    - Document title
    - Section count and headings
    - Estimated video scenes
    - Estimated duration
    - Content statistics

    This endpoint is designed for the "preview before generate" workflow.
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


@router.get("/upload/progress-stages")
async def get_progress_stages():
    """
    Get the defined stages for upload progress tracking.

    Returns stage names, progress percentages, and user-friendly messages
    for implementing progress indicators in the UI.
    """
    return get_upload_progress_stages()


@router.get("/document/supported-formats")
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


@router.post("/parse-only/document")
async def parse_document_only(input: DocumentInput):
    """
    Parse document and return scenes for review WITHOUT generating video.
    This allows users to review/edit scenes before triggering generation.
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
