# Backend API Quick Reference

## Running the Server

```bash
# Development
cd app
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Access**: http://localhost:8000

---

## Security

### CSRF Protection
All state-changing endpoints (POST, PUT, DELETE) require CSRF token validation.

**Get CSRF Token:**
```bash
curl http://localhost:8000/api/csrf-token
```

**Response:**
```json
{"csrf_token": "session_id:timestamp:signature"}
```

**Include in requests via:**
- `X-CSRF-Token` header, OR
- `csrf_token` form field, OR
- `csrf_token` JSON body field

**Bypass (Development Only):**
```bash
export CSRF_DISABLED=true
```

**Protected Endpoints:** All POST/PUT/DELETE requests except GET/HEAD/OPTIONS

---

## Rate Limiting

Rate limits are IP-based and configurable via environment variables.

| Endpoint Type | Default Limit | Environment Variable |
|--------------|---------------|---------------------|
| Default | 100/minute | RATE_LIMIT_DEFAULT |
| Upload | 5/minute | RATE_LIMIT_UPLOAD |
| Generate | 3/minute | RATE_LIMIT_GENERATE |
| Parse | 10/minute | RATE_LIMIT_PARSE |
| Tasks (polling) | 60/minute | RATE_LIMIT_TASKS |
| Health | 1000/minute | RATE_LIMIT_HEALTH |

**Rate Limit Headers:**
```
X-RateLimit-Limit: 10/minute
Retry-After: 60
```

**Disable Rate Limiting (Development):**
```bash
export RATE_LIMIT_ENABLED=false
```

**Exempt Routes:** `/static`, `/docs`, `/openapi.json`, `/redoc`

---

## Complete Endpoint Reference

### Security Endpoints

#### GET /api/csrf-token
Get a fresh CSRF token for state-changing requests.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Response:**
```json
{"csrf_token": "session_id:timestamp:signature"}
```

**Usage:**
```javascript
const response = await fetch('/api/csrf-token');
const {csrf_token} = await response.json();
// Include in subsequent POST/PUT/DELETE requests
```

---

### Document Input Endpoints

#### POST /api/validate/document
Validate document file before processing.

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** multipart/form-data

**Request:**
```bash
curl -X POST http://localhost:8000/api/validate/document \
  -H "X-CSRF-Token: {token}" \
  -F "file=@document.md"
```

**Response (Valid):**
```json
{
  "valid": true,
  "filename": "document.md",
  "preview": {
    "title": "Document Title",
    "section_count": 5,
    "word_count": 1234,
    "estimated_scenes": 12,
    "format_info": {
      "format": "markdown",
      "confidence": "high"
    }
  },
  "warnings": []
}
```

**Response (Invalid):**
```json
{
  "valid": false,
  "filename": "document.pdf",
  "errors": [
    "Unsupported file type: .pdf",
    "Only .md, .txt, .rst files are allowed"
  ],
  "warnings": []
}
```

**Validation Checks:**
- File extension (.md, .txt, .rst, .markdown)
- File size (max 10MB)
- Content type verification
- Binary content detection
- Document structure analysis

---

#### POST /api/preview/document
Generate detailed preview of document structure.

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** multipart/form-data

**Request:**
```bash
curl -X POST http://localhost:8000/api/preview/document \
  -H "X-CSRF-Token: {token}" \
  -F "file=@document.md"
```

**Response:**
```json
{
  "status": "success",
  "preview": {
    "title": "Getting Started with Python",
    "section_count": 8,
    "sections": [
      "Introduction",
      "Installation",
      "Basic Syntax"
    ],
    "word_count": 2500,
    "estimated_scenes": 15,
    "estimated_duration": "3-5 minutes",
    "format": "markdown",
    "filename": "document.md",
    "file_size": 12450,
    "has_lists": true,
    "has_code": true
  },
  "ready_for_generation": true,
  "recommendations": [
    "Document looks good for video generation!",
    "Consider splitting by H2 sections for multiple videos"
  ]
}
```

---

#### POST /api/parse/document
Parse document and generate video set (background task).

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/parse/document \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "content": "/path/to/document.md",
    "accent_color": "blue",
    "voice": "male",
    "video_count": 1,
    "split_strategy": "auto",
    "enable_ai_splitting": true
  }'
```

**Request Fields:**
- `content` (required): Document path
- `accent_color` (optional): blue|purple|orange|green|pink|cyan (default: blue)
- `voice` (optional): male|male_warm|female|female_friendly (default: male)
- `video_count` (optional): 1-10 (default: 1)
- `split_strategy` (optional): auto|ai|headers|paragraph|sentence|length (default: auto)
- `split_by_h2` (optional): Legacy boolean
- `enable_ai_splitting` (optional): Enable AI splitting (default: true)

**Response:**
```json
{
  "task_id": "doc_1639483920",
  "status": "started",
  "message": "Document parsing started"
}
```

**Security:** Path traversal protection, system directory blocking

---

#### POST /api/upload/document
Upload document file and generate video set.

**Rate Limit:** Upload (5/minute)
**CSRF Required:** Yes
**Content-Type:** multipart/form-data

**Request:**
```bash
curl -X POST http://localhost:8000/api/upload/document \
  -H "X-CSRF-Token: {token}" \
  -F "file=@document.md" \
  -F "accent_color=blue" \
  -F "voice=male" \
  -F "video_count=1"
```

**Form Fields:**
- `file` (required): Document file (.md, .txt, .rst)
- `accent_color` (optional): blue|purple|orange|green|pink|cyan
- `voice` (optional): male|male_warm|female|female_friendly
- `video_count` (optional): 1-10

**Response:**
```json
{
  "task_id": "upload_1639483920123_a1b2c3d4",
  "status": "started",
  "message": "File 'document.md' uploaded successfully and processing started",
  "filename": "document.md",
  "size": 12450
}
```

**Limits:** Max file size 10MB, allowed extensions: .md, .txt, .rst, .markdown

---

#### POST /api/parse-only/document
Parse document and return scenes WITHOUT generating video.

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/parse-only/document \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "content": "/path/to/document.md",
    "accent_color": "blue",
    "voice": "male",
    "video_count": 1
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "Document parsed successfully",
  "data": {
    "set_id": "doc_set",
    "set_name": "Document Title",
    "videos": [
      {
        "video_id": "video_1",
        "title": "Section 1",
        "scenes": [
          {
            "type": "title",
            "title": "Introduction",
            "subtitle": "Getting Started"
          }
        ]
      }
    ]
  },
  "scene_count": 12,
  "video_count": 1
}
```

---

#### GET /api/upload/progress-stages
Get upload progress stage definitions.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Response:**
```json
{
  "stages": [
    {
      "name": "uploading",
      "progress": 20,
      "message": "Uploading file..."
    },
    {
      "name": "validating",
      "progress": 40,
      "message": "Validating document..."
    }
  ]
}
```

---

#### GET /api/document/supported-formats
Get list of supported document formats.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Response:**
```json
{
  "formats": [
    {
      "extension": ".md",
      "name": "Markdown",
      "mime_types": ["text/markdown", "text/x-markdown"],
      "description": "Best format for structured content",
      "recommended": true
    }
  ],
  "max_file_size": "10MB",
  "tips": [
    "Use Markdown for best results",
    "Include ## headings for sections"
  ]
}
```

---

### YouTube Input Endpoints

#### POST /api/youtube/validate
Validate YouTube URL.

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/youtube/validate \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{"url": "https://youtube.com/watch?v=VIDEO_ID"}'
```

**Response (Valid):**
```json
{
  "is_valid": true,
  "video_id": "VIDEO_ID",
  "normalized_url": "https://www.youtube.com/watch?v=VIDEO_ID",
  "error": null,
  "error_code": null
}
```

**Response (Invalid):**
```json
{
  "is_valid": false,
  "video_id": null,
  "normalized_url": null,
  "error": "Invalid YouTube URL format",
  "error_code": "INVALID_FORMAT"
}
```

**Supported URL Formats:**
- `https://youtube.com/watch?v=VIDEO_ID`
- `https://www.youtube.com/watch?v=VIDEO_ID`
- `https://youtu.be/VIDEO_ID`
- `https://m.youtube.com/watch?v=VIDEO_ID`

---

#### POST /api/youtube/preview
Get preview information for YouTube video.

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/youtube/preview \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "url": "https://youtube.com/watch?v=VIDEO_ID",
    "include_transcript_preview": true,
    "transcript_language": "en"
  }'
```

**Response:**
```json
{
  "status": "success",
  "video_id": "VIDEO_ID",
  "normalized_url": "https://www.youtube.com/watch?v=VIDEO_ID",
  "preview": {
    "title": "Python Tutorial for Beginners",
    "channel": "TechChannel",
    "duration_seconds": 1200,
    "duration_formatted": "20:00",
    "thumbnail_url": "https://i.ytimg.com/vi/VIDEO_ID/hqdefault.jpg",
    "has_transcript": true,
    "estimated_scenes": 25,
    "generation_estimate": "5-8 minutes",
    "transcript_preview": {
      "segments": [...],
      "total_words": 2500
    }
  }
}
```

---

#### POST /api/youtube/transcript-preview
Get transcript preview for YouTube video.

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/youtube/transcript-preview \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "url": "https://youtube.com/watch?v=VIDEO_ID",
    "transcript_language": "en"
  }'
```

**Response:**
```json
{
  "status": "success",
  "video_id": "VIDEO_ID",
  "available": true,
  "languages": ["en", "es", "fr"],
  "requested_language": "en",
  "preview": {
    "segments": [
      {
        "text": "Welcome to this tutorial",
        "start": 0.0,
        "duration": 2.5
      }
    ],
    "total_segments": 150,
    "total_words": 2500,
    "language": "en",
    "is_generated": false,
    "preview_text": "Welcome to this tutorial..."
  }
}
```

---

#### GET /api/youtube/estimate/{video_id}
Get generation time and scene count estimates.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Request:**
```bash
curl http://localhost:8000/api/youtube/estimate/VIDEO_ID
```

**Response:**
```json
{
  "video_id": "VIDEO_ID",
  "source_duration_seconds": 1200,
  "source_duration_formatted": "20:00",
  "estimated_scenes": 25,
  "generation_estimate": {
    "min_minutes": 5,
    "max_minutes": 8,
    "display": "5-8 minutes"
  },
  "has_accurate_duration": true
}
```

---

#### POST /api/parse/youtube
Parse YouTube video and generate script (background task).

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/parse/youtube \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "url": "https://youtube.com/watch?v=VIDEO_ID",
    "duration": 60,
    "accent_color": "blue",
    "voice": "male",
    "scene_duration": 12
  }'
```

**Request Fields:**
- `url` (required): YouTube video URL
- `duration` (optional): Target duration 30-600 seconds (default: 60)
- `accent_color` (optional): blue|purple|orange|green|pink|cyan
- `voice` (optional): male|male_warm|female|female_friendly
- `scene_duration` (optional): 5-30 seconds (default: 12)

**Response:**
```json
{
  "task_id": "yt_1639483920",
  "status": "started",
  "message": "YouTube parsing started"
}
```

---

#### POST /api/parse-only/youtube
Parse YouTube video and return scenes WITHOUT generating video.

**Rate Limit:** Parse (10/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/parse-only/youtube \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "url": "https://youtube.com/watch?v=VIDEO_ID",
    "accent_color": "blue"
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "YouTube video parsed successfully",
  "data": {
    "set_id": "yt_set",
    "videos": [...]
  },
  "scene_count": 15,
  "video_count": 1
}
```

---

### Video Generation Endpoints

#### POST /api/generate
Generate videos from video set (background task).

**Rate Limit:** Generate (3/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "set_id": "my_videos",
    "set_name": "Tutorial Series",
    "videos": [
      {
        "video_id": "video_1",
        "title": "Introduction",
        "scenes": [
          {
            "type": "title",
            "title": "Welcome",
            "subtitle": "Getting Started"
          }
        ],
        "voice": "male"
      }
    ],
    "accent_color": "blue",
    "languages": ["en"]
  }'
```

**Request Fields:**
- `set_id` (required): Unique identifier (alphanumeric, dash, underscore)
- `set_name` (required): Display name (1-200 chars)
- `videos` (required): Array of video objects (min 1)
- `accent_color` (optional): blue|purple|orange|green|pink|cyan (default: blue)
- `languages` (optional): Array of language codes (default: ["en"])
- `source_language` (optional): Source language code (default: "en")
- `translation_method` (optional): claude|google|manual (default: "claude")

**Video Object:**
- `video_id` (required): Unique identifier
- `title` (required): Video title
- `scenes` (required): Array of scene objects (min 1)
- `voice` (optional): male|male_warm|female|female_friendly
- `voices` (optional): Array of voices for rotation
- `duration` (optional): Target duration in seconds

**Response:**
```json
{
  "task_id": "gen_1639483920",
  "status": "started",
  "message": "Video generation started"
}
```

---

#### POST /api/generate/multilingual
Generate multilingual videos from video set.

**Rate Limit:** Generate (3/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/generate/multilingual \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "video_set": {
      "set_id": "tutorial",
      "set_name": "Python Tutorial",
      "videos": [...],
      "accent_color": "blue"
    },
    "target_languages": ["en", "es", "fr"],
    "source_language": "en",
    "translation_method": "claude",
    "language_voices": {
      "en": "male",
      "es": "male",
      "fr": "female"
    }
  }'
```

**Request Fields:**
- `video_set` (required): VideoSet object
- `target_languages` (required): Array of language codes
- `source_language` (optional): Source language (default: "en")
- `translation_method` (optional): claude|google (default: "claude")
- `language_voices` (optional): Per-language voice mapping

**Response:**
```json
{
  "task_id": "ml_1639483920",
  "status": "started",
  "message": "Multilingual generation started for 3 languages",
  "languages": ["en", "es", "fr"],
  "source_language": "en"
}
```

---

### Task Status & Progress Endpoints

#### GET /api/tasks/{task_id}
Get task status and progress.

**Rate Limit:** Tasks (60/minute)
**CSRF Required:** No

**Request:**
```bash
curl http://localhost:8000/api/tasks/doc_1639483920
```

**Response:**
```json
{
  "task_id": "doc_1639483920",
  "status": "processing",
  "progress": 45,
  "message": "Generating audio...",
  "type": "document",
  "errors": null,
  "result": null
}
```

**Status Values:**
- `processing`: Task is running
- `complete`: Task finished successfully
- `failed`: Task failed with errors

---

#### GET /api/tasks/{task_id}/stream
Stream real-time progress via Server-Sent Events.

**Rate Limit:** None (SSE stream)
**CSRF Required:** No

**Request:**
```bash
curl -N http://localhost:8000/api/tasks/doc_1639483920/stream
```

**Response (SSE Stream):**
```
data: {"task_id":"doc_1639483920","status":"processing","progress":20,"stage":"input_adaptation","stage_display":"Preparation","stage_progress":80,"message":"Preparing input..."}

data: {"task_id":"doc_1639483920","status":"processing","progress":35,"stage":"content_parsing","stage_display":"Scenes","stage_progress":50,"message":"Parsing scenes..."}

data: {"task_id":"doc_1639483920","status":"complete","progress":100,"stage":"output_handling","stage_display":"Finalization","stage_progress":100,"message":"Complete","final":true}
```

**Event Data Fields:**
- `task_id`: Task identifier
- `status`: processing|complete|failed
- `progress`: Overall progress 0-100
- `stage`: Internal stage name
- `stage_display`: User-friendly stage name
- `stage_progress`: Stage-specific progress 0-100
- `message`: Current operation message
- `final`: true when task completes/fails
- `errors`: Array of error messages (if failed)
- `result`: Task result data (if complete)

**Stage Names:**
- Preparation → input_adaptation
- Scenes → content_parsing
- Narration → script_generation
- Synthesis → audio_generation
- Composition → video_generation
- Finalization → output_handling

---

### Job Management Endpoints

#### GET /api/videos/jobs
Get all video generation jobs.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No
**Accept Header:** application/json (for JSON) or text/html (for HTMX)

**Request:**
```bash
curl -H "Accept: application/json" \
  http://localhost:8000/api/videos/jobs
```

**Response:**
```json
{
  "stats": {
    "active": 2,
    "queued": 1,
    "completed": 5,
    "failed": 0
  },
  "active_jobs": [
    {
      "id": "doc_1639483920",
      "document": "tutorial.md",
      "current_stage": "Synthesis",
      "progress": 65,
      "elapsed": "2:15",
      "stages": [
        {
          "name": "Preparation",
          "status": "completed",
          "duration": "0.5s"
        },
        {
          "name": "Synthesis",
          "status": "active",
          "progress": 75
        }
      ],
      "status": "running",
      "errors": [],
      "warnings": []
    }
  ],
  "queued_jobs": [...],
  "completed_jobs": [...],
  "failed_jobs": [...]
}
```

**Job Object Fields:**
- `id`: Job/task ID
- `document`: Source document/video name
- `current_stage`: User-friendly stage name
- `progress`: Overall progress 0-100
- `elapsed`: Elapsed time (M:SS or H:MM:SS)
- `total_duration`: Total duration for completed jobs
- `stages`: Array of stage status objects
- `status`: pending|running|completed|failed|cancelled
- `errors`: Array of error messages
- `error_details`: Detailed error information with stage context
- `warnings`: Array of warning messages
- `created_at`: ISO 8601 timestamp

---

#### GET /api/videos/jobs/{job_id}
Get detailed status for a specific job.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Request:**
```bash
curl http://localhost:8000/api/videos/jobs/doc_1639483920
```

**Response:**
```json
{
  "status": "success",
  "job": {
    "id": "doc_1639483920",
    "document": "tutorial.md",
    "current_stage": "Synthesis",
    "progress": 65,
    "elapsed": "2:15",
    "stages": [...],
    "status": "running",
    "input_config": {
      "input_type": "document",
      "source": "/path/to/tutorial.md",
      "accent_color": "blue",
      "voice": "male"
    },
    "result": null,
    "errors": [],
    "warnings": []
  }
}
```

---

#### GET /api/videos/jobs/{job_id}/events
Stream real-time events for a specific job via SSE.

**Rate Limit:** None (SSE stream)
**CSRF Required:** No

**Request:**
```bash
curl -N http://localhost:8000/api/videos/jobs/doc_1639483920/events
```

**Response (SSE Stream):**
```
data: {"job_id":"doc_1639483920","status":"running","progress":45,"current_stage":"Synthesis","stages":[...]}

data: {"job_id":"doc_1639483920","status":"completed","progress":100,"final":true}
```

---

### Template Management Endpoints

#### POST /api/templates/save
Save a video configuration template.

**Rate Limit:** Default (100/minute)
**CSRF Required:** Yes
**Content-Type:** application/json

**Request:**
```bash
curl -X POST http://localhost:8000/api/templates/save \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {token}" \
  -d '{
    "name": "Tech Tutorial Template",
    "description": "Standard template for technical tutorials",
    "mode": "set",
    "config": {
      "accent_color": "blue",
      "voice": "male",
      "scene_types": ["title", "command", "list"]
    }
  }'
```

**Request Fields:**
- `name` (required): Template name
- `description` (optional): Template description
- `mode` (required): single|set
- `config` (required): Template configuration object

**Response:**
```json
{
  "success": true,
  "message": "Template saved successfully",
  "template_id": "tmpl_1639483920"
}
```

**Note:** Currently templates are stored client-side in localStorage. Server-side storage is planned.

---

#### GET /api/templates/list
Get list of saved templates.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Request:**
```bash
curl http://localhost:8000/api/templates/list
```

**Response:**
```json
{
  "templates": [],
  "message": "Templates are stored client-side in browser localStorage"
}
```

---

#### DELETE /api/templates/{template_id}
Delete a template.

**Rate Limit:** Default (100/minute)
**CSRF Required:** Yes

**Request:**
```bash
curl -X DELETE http://localhost:8000/api/templates/tmpl_1639483920 \
  -H "X-CSRF-Token: {token}"
```

**Response:**
```json
{
  "success": true,
  "message": "Template deleted successfully"
}
```

---

### Metadata Endpoints

#### GET /api/scene-types
Get available scene types.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Response:**
```json
{
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
```

---

#### GET /api/voices
Get available voices.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Response:**
```json
[
  {
    "id": "male",
    "name": "Andrew (Male)",
    "description": "Professional, confident"
  },
  {
    "id": "male_warm",
    "name": "Brandon (Male Warm)",
    "description": "Warm, engaging"
  },
  {
    "id": "female",
    "name": "Aria (Female)",
    "description": "Clear, crisp"
  },
  {
    "id": "female_friendly",
    "name": "Ava (Female Friendly)",
    "description": "Friendly, pleasant"
  }
]
```

---

#### GET /api/colors
Get available accent colors.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Response:**
```json
["blue", "purple", "orange", "green", "pink", "cyan"]
```

---

#### GET /api/languages
Get all supported languages (28+).

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Response:**
```json
{
  "languages": [
    {
      "code": "en",
      "name": "English",
      "name_local": "English",
      "rtl": false,
      "voice_count": 4,
      "voices": ["male", "male_warm", "female", "female_friendly"]
    },
    {
      "code": "es",
      "name": "Spanish",
      "name_local": "Español",
      "rtl": false,
      "voice_count": 2,
      "voices": ["male", "female"]
    }
  ],
  "total": 28
}
```

---

#### GET /api/languages/{lang_code}/voices
Get available voices for a specific language.

**Rate Limit:** Default (100/minute)
**CSRF Required:** No

**Request:**
```bash
curl http://localhost:8000/api/languages/es/voices
```

**Response:**
```json
{
  "status": "success",
  "language": "es",
  "voices": [
    {
      "id": "male",
      "name": "Alvaro",
      "display_name": "Alvaro (Male)",
      "description": "Professional, confident",
      "gender": "male",
      "gender_symbol": "♂",
      "edge_tts_id": "es-ES-AlvaroNeural",
      "sample_url": "/static/audio/samples/es_male.mp3"
    },
    {
      "id": "female",
      "name": "Elvira",
      "display_name": "Elvira (Female)",
      "description": "Clear, friendly",
      "gender": "female",
      "gender_symbol": "♀",
      "edge_tts_id": "es-ES-ElviraNeural",
      "sample_url": "/static/audio/samples/es_female.mp3"
    }
  ],
  "voice_count": 2
}
```

---

### Health & System Endpoints

#### GET /api/health
Health check endpoint.

**Rate Limit:** Health (1000/minute)
**CSRF Required:** No

**Response:**
```json
{
  "status": "healthy",
  "service": "video-generation",
  "pipeline": "unified",
  "version": "2.0.0",
  "stages": 6,
  "features": {
    "multilingual": true,
    "document_parsing": true,
    "youtube_parsing": true,
    "programmatic_api": true,
    "state_persistence": true,
    "auto_resume": true,
    "templates": true
  }
}
```

---

## Error Responses

All endpoints return consistent error formats:

### 400 Bad Request
```json
{
  "detail": "Invalid input type",
  "field": "input_type",
  "allowed_values": ["document", "youtube", "programmatic"]
}
```

### 403 Forbidden (CSRF)
```json
{
  "detail": "CSRF token validation failed. Please refresh the page and try again."
}
```

### 404 Not Found
```json
{
  "detail": "Task not found"
}
```

### 413 Payload Too Large
```json
{
  "detail": "File too large. Maximum size is 10MB"
}
```

### 429 Too Many Requests
```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please slow down and try again later.",
  "limit": "10/minute",
  "endpoint": "/api/parse/document",
  "retry_after": "Please wait before making another request"
}
```

**Headers:**
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 10/minute
```

### 500 Internal Server Error
```json
{
  "detail": "Parse failed: Could not read document",
  "error_code": "PARSE_ERROR"
}
```

---

## HTMX Examples

### Fetch CSRF Token
```html
<script>
  // Fetch CSRF token on page load
  fetch('/api/csrf-token')
    .then(r => r.json())
    .then(data => {
      window.csrfToken = data.csrf_token;
    });
</script>
```

### Document Upload with Progress
```html
<form hx-post="/api/upload/document"
      hx-encoding="multipart/form-data"
      hx-target="#result">
  <input type="file" name="file" accept=".md,.txt,.rst">
  <select name="accent_color">
    <option value="blue">Blue</option>
    <option value="purple">Purple</option>
  </select>
  <select name="voice">
    <option value="male">Andrew (Male)</option>
    <option value="female">Aria (Female)</option>
  </select>
  <input type="hidden" name="csrf_token" value="${window.csrfToken}">
  <button type="submit">Upload & Generate</button>
</form>

<div id="result"></div>
```

### Progress Polling
```html
<div id="progress"
     hx-get="/api/tasks/{task_id}"
     hx-trigger="every 2s"
     hx-swap="innerHTML">
  <div class="progress-bar" style="width: {progress}%"></div>
  <p>{message}</p>
</div>
```

### SSE Progress Stream
```html
<div id="live-progress"></div>

<script>
  const eventSource = new EventSource('/api/tasks/{task_id}/stream');

  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    document.getElementById('live-progress').innerHTML = `
      <div>Progress: ${data.progress}%</div>
      <div>Stage: ${data.stage_display}</div>
      <div>Message: ${data.message}</div>
    `;

    if (data.final) {
      eventSource.close();
    }
  };
</script>
```

---

## Environment Variables

### Security
```bash
# CSRF protection
export CSRF_SECRET="your-secret-key-here"  # Auto-generated if not set
export CSRF_DISABLED="false"  # Set to "true" for development only

# Rate limiting
export RATE_LIMIT_ENABLED="true"
export RATE_LIMIT_DEFAULT="100/minute"
export RATE_LIMIT_UPLOAD="5/minute"
export RATE_LIMIT_GENERATE="3/minute"
export RATE_LIMIT_PARSE="10/minute"
export RATE_LIMIT_TASKS="60/minute"
export RATE_LIMIT_HEALTH="1000/minute"
```

### API Configuration
```bash
export API_HOST="0.0.0.0"
export API_PORT="8000"
```

### AI Services (Optional)
```bash
# For AI narration enhancement
export ANTHROPIC_API_KEY="sk-ant-..."

# For Google Translate (alternative to Claude translation)
export GOOGLE_TRANSLATE_API_KEY="..."
```

---

## Quick Test Workflow

### 1. Start Server
```bash
cd /path/to/video_gen/app
uvicorn main:app --reload --port 8000
```

### 2. Health Check
```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{"status":"healthy","service":"video-generation","version":"2.0.0"}
```

### 3. Get CSRF Token
```bash
TOKEN=$(curl -s http://localhost:8000/api/csrf-token | jq -r '.csrf_token')
echo $TOKEN
```

### 4. Test Document Validation
```bash
curl -X POST http://localhost:8000/api/validate/document \
  -H "X-CSRF-Token: $TOKEN" \
  -F "file=@README.md"
```

### 5. Upload Document
```bash
curl -X POST http://localhost:8000/api/upload/document \
  -H "X-CSRF-Token: $TOKEN" \
  -F "file=@README.md" \
  -F "accent_color=blue" \
  -F "voice=male" \
  -F "video_count=1"
```

Save the `task_id` from response.

### 6. Monitor Progress (Polling)
```bash
TASK_ID="doc_1639483920"
curl http://localhost:8000/api/tasks/$TASK_ID
```

### 7. Monitor Progress (SSE Stream)
```bash
curl -N http://localhost:8000/api/tasks/$TASK_ID/stream
```

### 8. Get All Jobs
```bash
curl -H "Accept: application/json" \
  http://localhost:8000/api/videos/jobs
```

---

## Integration Architecture

### Unified Pipeline (6 Stages)

All video generation flows through the unified pipeline:

```
┌─────────────────────┐
│  Input Adaptation   │  Normalize input (document/YouTube/programmatic)
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Content Parsing    │  Parse scenes from input
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│ Script Generation   │  Generate narration (AI-enhanced)
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Audio Generation   │  Text-to-speech synthesis
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Video Generation   │  Render video scenes
└──────────┬──────────┘
           │
┌──────────▼──────────┘
│  Output Handling    │  Finalize and store results
└─────────────────────┘
```

### State Persistence

All tasks are persisted to disk with automatic recovery:

- **Location**: `pipeline_states/{task_id}.json`
- **Auto-resume**: Tasks can resume after server restart
- **Progress tracking**: Stage-level and overall progress
- **Error handling**: Detailed error capture per stage

---

## API Integration Examples

### Python Client
```python
import requests

class VideoGenClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.csrf_token = self._get_csrf_token()

    def _get_csrf_token(self):
        response = requests.get(f"{self.base_url}/api/csrf-token")
        return response.json()["csrf_token"]

    def upload_document(self, file_path, accent_color="blue", voice="male"):
        with open(file_path, "rb") as f:
            files = {"file": f}
            data = {
                "accent_color": accent_color,
                "voice": voice,
                "video_count": 1
            }
            headers = {"X-CSRF-Token": self.csrf_token}

            response = requests.post(
                f"{self.base_url}/api/upload/document",
                files=files,
                data=data,
                headers=headers
            )
            return response.json()

    def get_task_status(self, task_id):
        response = requests.get(f"{self.base_url}/api/tasks/{task_id}")
        return response.json()

    def stream_progress(self, task_id):
        """Generator that yields progress updates"""
        response = requests.get(
            f"{self.base_url}/api/tasks/{task_id}/stream",
            stream=True
        )

        for line in response.iter_lines():
            if line and line.startswith(b"data: "):
                yield json.loads(line[6:])

# Usage
client = VideoGenClient()
result = client.upload_document("tutorial.md")
task_id = result["task_id"]

for progress in client.stream_progress(task_id):
    print(f"Progress: {progress['progress']}% - {progress['message']}")
    if progress.get("final"):
        break
```

### JavaScript/TypeScript Client
```typescript
class VideoGenClient {
  private baseUrl: string;
  private csrfToken: string | null = null;

  constructor(baseUrl = 'http://localhost:8000') {
    this.baseUrl = baseUrl;
  }

  async init() {
    const response = await fetch(`${this.baseUrl}/api/csrf-token`);
    const data = await response.json();
    this.csrfToken = data.csrf_token;
  }

  async uploadDocument(file: File, options = {}) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('accent_color', options.accentColor || 'blue');
    formData.append('voice', options.voice || 'male');
    formData.append('video_count', String(options.videoCount || 1));

    const response = await fetch(`${this.baseUrl}/api/upload/document`, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': this.csrfToken!
      },
      body: formData
    });

    return response.json();
  }

  async getTaskStatus(taskId: string) {
    const response = await fetch(`${this.baseUrl}/api/tasks/${taskId}`);
    return response.json();
  }

  streamProgress(taskId: string, onProgress: (data: any) => void) {
    const eventSource = new EventSource(
      `${this.baseUrl}/api/tasks/${taskId}/stream`
    );

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      onProgress(data);

      if (data.final) {
        eventSource.close();
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };

    return eventSource;
  }
}

// Usage
const client = new VideoGenClient();
await client.init();

const result = await client.uploadDocument(fileInput.files[0]);
client.streamProgress(result.task_id, (data) => {
  console.log(`${data.progress}%: ${data.message}`);
});
```

---

## Endpoint Summary Table

| Endpoint | Method | Rate Limit | CSRF | Purpose |
|----------|--------|------------|------|---------|
| `/api/csrf-token` | GET | Default | No | Get CSRF token |
| `/api/validate/document` | POST | Parse | Yes | Validate document file |
| `/api/preview/document` | POST | Parse | Yes | Preview document structure |
| `/api/parse/document` | POST | Parse | Yes | Parse document (background) |
| `/api/upload/document` | POST | Upload | Yes | Upload & process document |
| `/api/parse-only/document` | POST | Parse | Yes | Parse without generating |
| `/api/upload/progress-stages` | GET | Default | No | Get progress stage definitions |
| `/api/document/supported-formats` | GET | Default | No | Get supported file formats |
| `/api/youtube/validate` | POST | Parse | Yes | Validate YouTube URL |
| `/api/youtube/preview` | POST | Parse | Yes | Get video preview |
| `/api/youtube/transcript-preview` | POST | Parse | Yes | Get transcript preview |
| `/api/youtube/estimate/{video_id}` | GET | Default | No | Estimate generation time |
| `/api/parse/youtube` | POST | Parse | Yes | Parse YouTube (background) |
| `/api/parse-only/youtube` | POST | Parse | Yes | Parse without generating |
| `/api/generate` | POST | Generate | Yes | Generate videos |
| `/api/generate/multilingual` | POST | Generate | Yes | Generate multilingual videos |
| `/api/tasks/{task_id}` | GET | Tasks | No | Get task status |
| `/api/tasks/{task_id}/stream` | GET | None | No | Stream task progress (SSE) |
| `/api/videos/jobs` | GET | Default | No | Get all jobs |
| `/api/videos/jobs/{job_id}` | GET | Default | No | Get job details |
| `/api/videos/jobs/{job_id}/events` | GET | None | No | Stream job events (SSE) |
| `/api/templates/save` | POST | Default | Yes | Save template |
| `/api/templates/list` | GET | Default | No | List templates |
| `/api/templates/{template_id}` | DELETE | Default | Yes | Delete template |
| `/api/scene-types` | GET | Default | No | Get scene types |
| `/api/voices` | GET | Default | No | Get available voices |
| `/api/colors` | GET | Default | No | Get accent colors |
| `/api/languages` | GET | Default | No | Get all languages |
| `/api/languages/{lang_code}/voices` | GET | Default | No | Get language-specific voices |
| `/api/health` | GET | Health | No | Health check |

---

**Full Documentation**:
- Architecture: `docs/architecture/`
- API Design: `docs/API_DESIGN.md`
- Production Readiness: `docs/PRODUCTION_READINESS.md`
