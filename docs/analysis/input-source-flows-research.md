# Input Source Flows - Architecture Research

**Research Date:** November 22, 2025
**Agent:** Researcher
**Objective:** Analyze input adapter architecture and identify gaps/opportunities for elegant input source type flows

---

## Executive Summary

The video_gen system implements a well-structured adapter pattern for handling multiple input sources. The architecture supports **five input types** (document, youtube, wizard, yaml, programmatic) through a unified `InputAdapter` base class. However, there are significant gaps between the backend adapter capabilities and the API/UI exposure, creating opportunities for a more elegant and consistent input flow experience.

---

## 1. Current Architecture Analysis

### 1.1 Input Adapter Pattern

**Location:** `/mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen/video_gen/input_adapters/`

```
input_adapters/
|-- __init__.py          # Exports all adapters
|-- base.py              # Abstract InputAdapter class
|-- document.py          # DocumentAdapter (1012 lines, AI-enhanced)
|-- youtube.py           # YouTubeAdapter (422 lines)
|-- wizard.py            # InteractiveWizard (643 lines)
|-- yaml_file.py         # YAMLFileAdapter (1159 lines, template support)
|-- programmatic.py      # ProgrammaticAdapter (103 lines)
|-- compat.py            # Backward compatibility layer (489 lines)
```

### 1.2 Base Architecture

**InputAdapter (Abstract Base Class):**
```python
class InputAdapter(ABC):
    async def adapt(source: Any, **kwargs) -> InputAdapterResult
    async def validate_source(source: Any) -> bool
    def supports_format(format_type: str) -> bool
```

**InputAdapterResult:**
```python
@dataclass
class InputAdapterResult:
    success: bool
    video_set: Optional[VideoSet] = None
    error: Optional[str] = None
    metadata: dict = None
```

### 1.3 InputConfig Model

**Location:** `/mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen/video_gen/shared/models.py` (lines 145-185)

```python
@dataclass
class InputConfig:
    input_type: Literal["document", "youtube", "wizard", "yaml", "programmatic"]
    source: str
    accent_color: str = "blue"
    voice: str = "male"
    languages: List[str] = field(default_factory=lambda: ["en"])
    output_dir: Optional[Path] = None
    auto_generate: bool = True
    skip_review: bool = False
    resume_from: Optional[str] = None
    use_ai_narration: bool = False
    video_count: Optional[int] = 1
    split_by_h2: bool = False
```

---

## 2. API Endpoint Inventory

### 2.1 Current Endpoints (app/main.py)

| Endpoint | Method | Input Model | Purpose |
|----------|--------|-------------|---------|
| `/api/parse/document` | POST | `DocumentInput` | Parse document and generate video (async) |
| `/api/upload/document` | POST | FormData | Upload file and parse |
| `/api/parse-only/document` | POST | `DocumentInput` | Parse without generation (preview) |
| `/api/parse/youtube` | POST | `YouTubeInput` | Parse YouTube video (async) |
| `/api/parse-only/youtube` | POST | `YouTubeInput` | Parse without generation (preview) |
| `/api/generate` | POST | `VideoSet` | Generate videos from video set |
| `/api/scene-types` | GET | - | List available scene types |
| `/api/voices` | GET | - | List available voices |
| `/api/colors` | GET | - | List available accent colors |
| `/api/languages` | GET | - | List available languages |
| `/api/languages/{lang}/voices` | GET | - | Get voices for language |
| `/api/generate/multilingual` | POST | - | Multilingual video generation |
| `/api/templates/save` | POST | - | Save template |
| `/api/templates/list` | GET | - | List templates |
| `/api/templates/{id}` | DELETE | - | Delete template |
| `/api/tasks/{task_id}` | GET | - | Get task status |
| `/api/tasks/{task_id}/stream` | GET | - | Stream task progress |
| `/api/videos/jobs` | GET | - | List video jobs |
| `/api/health` | GET | - | Health check |

### 2.2 Input Models

**DocumentInput (Pydantic):**
```python
class DocumentInput(BaseModel):
    content: str  # File path or text
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    video_count: Optional[int] = 1  # 1-10
    generate_set: Optional[bool] = False
```

**YouTubeInput (Pydantic):**
```python
class YouTubeInput(BaseModel):
    url: str
    duration: Optional[int] = 60  # 30-600
    accent_color: Optional[str] = "blue"
```

---

## 3. Gap Analysis

### 3.1 Missing API Endpoints

| Gap | Description | Impact |
|-----|-------------|--------|
| **No Wizard API** | `InteractiveWizard` adapter exists but has no REST endpoint | CLI-only; no web wizard |
| **No Programmatic API** | `ProgrammaticAdapter` exists but no endpoint | Cannot use builder pattern via API |
| **No YAML Upload API** | `YAMLFileAdapter` exists but no dedicated endpoint | Must use document endpoint with workaround |
| **No Unified Input Source API** | No single endpoint to detect/route input types | Client must know which endpoint to use |

### 3.2 Naming Inconsistencies

| Component | Backend Name | API Name | UI Name |
|-----------|-------------|----------|---------|
| Input config | `InputConfig` | `DocumentInput`/`YouTubeInput` | `inputMethod` |
| Input type | `input_type` | `content`/`url` (implied) | `inputMethod` |
| Voice option | `voice` | `voice` | `voice` |
| Color option | `accent_color` | `accent_color` | `accentColor` |

### 3.3 UI/UX Gaps

**Current UI Flow (from templates analysis):**

1. **Home Page (`home.html`):** Shows 3 cards - Document, YouTube, Wizard
2. **Create Page (`create.html`):** Shows 4 input method buttons - Manual, Document, YouTube, YAML
3. **Create Unified (`create-unified.html`):** Shows 3 cards - Document, YouTube, YAML

**Inconsistencies:**
- Wizard shown on home but not in create-unified
- Manual option in create.html but not home
- No programmatic option in any UI
- Different card layouts/counts between pages

### 3.4 Missing Modern UX Patterns

From THREE_INPUT_METHODS_GUIDE.md, the system documents 4 methods but:

1. **No drag-and-drop file upload** - Current file input is basic
2. **No paste detection** - Cannot paste markdown/URLs and auto-detect
3. **No input source preview** - Limited preview before processing
4. **No unified wizard flow** - Separate pages vs. single wizard
5. **No recent inputs** - No history of recently used sources
6. **No template gallery** - Templates exist but no visual gallery

---

## 4. Integration Points

### 4.1 Pipeline Integration

**Current Flow:**
```
API Endpoint -> InputConfig -> Pipeline.execute(input_config) -> VideoSet
```

**Pipeline Location:** `/mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen/video_gen/pipeline/`

The pipeline accepts `InputConfig` and routes to appropriate adapter based on `input_type`.

### 4.2 Adapter-to-Pipeline Mapping

| input_type | Adapter Class | Pipeline Stage |
|------------|---------------|----------------|
| document | `DocumentAdapter` | Stage 1: Input Parsing |
| youtube | `YouTubeAdapter` | Stage 1: Input Parsing |
| wizard | `InteractiveWizard` | Stage 1: Input Parsing |
| yaml | `YAMLFileAdapter` | Stage 1: Input Parsing |
| programmatic | `ProgrammaticAdapter` | Stage 1: Input Parsing |

### 4.3 Compatibility Layer

**compat.py provides:**
- Synchronous `parse()` wrapper for async `adapt()`
- `BackwardCompatibleVideoSet` for legacy code
- `BackwardCompatibleVideoConfig` for scene access
- Factory function `get_adapter(type)` for type-based instantiation

---

## 5. Modern Convention Recommendations

### 5.1 Unified Input Source API

**Proposed Endpoint:** `POST /api/input/detect`

```python
class InputSourceRequest(BaseModel):
    content: str  # URL, file path, or inline content
    hint: Optional[str] = None  # Optional type hint

class InputSourceResponse(BaseModel):
    detected_type: str  # document, youtube, yaml, etc.
    confidence: float  # 0.0-1.0
    suggested_endpoint: str
    preview: Optional[dict]  # Quick preview data
```

### 5.2 Unified Input Flow Endpoint

**Proposed Endpoint:** `POST /api/input/process`

```python
class UnifiedInputRequest(BaseModel):
    source_type: Literal["document", "youtube", "wizard", "yaml", "programmatic"]
    source: str  # File path, URL, or inline data
    options: InputOptions
    action: Literal["parse_only", "generate"]  # Preview vs full generation

class InputOptions(BaseModel):
    accent_color: str = "blue"
    voice: str = "male"
    languages: List[str] = ["en"]
    video_count: int = 1
    use_ai_narration: bool = False
```

### 5.3 Wizard API Endpoint

**Proposed Endpoint:** `POST /api/wizard/step`

```python
class WizardStepRequest(BaseModel):
    session_id: Optional[str] = None  # Resume session
    step: int
    response: dict  # User's response to current step

class WizardStepResponse(BaseModel):
    session_id: str
    current_step: int
    total_steps: int
    question: dict  # Next question
    suggestions: List[str]
    can_proceed: bool
    preview: Optional[dict]
```

### 5.4 UI/UX Modernization

**1. Smart Input Detection:**
```javascript
// Auto-detect paste content
async function handlePaste(e) {
    const text = e.clipboardData.getData('text');
    const detected = await fetch('/api/input/detect', {
        method: 'POST',
        body: JSON.stringify({ content: text })
    });
    // Auto-select appropriate input method
}
```

**2. Unified Stepper Flow:**
```
Step 1: Choose/Detect Input Source
Step 2: Configure Options (voice, color, languages)
Step 3: Preview Content (editable scenes)
Step 4: Generate or Download YAML
```

**3. Input Method Cards (Consistent):**
```html
<!-- All pages should show same 5 methods -->
<div class="grid grid-cols-5 gap-4">
    <InputCard type="document" icon="file" />
    <InputCard type="youtube" icon="video" />
    <InputCard type="wizard" icon="wand" />
    <InputCard type="yaml" icon="code" />
    <InputCard type="programmatic" icon="terminal" />
</div>
```

---

## 6. Recommendations Summary

### 6.1 High Priority

1. **Add `/api/parse/wizard`** - Enable web-based wizard flow
2. **Add `/api/parse/yaml`** - Dedicated YAML processing endpoint
3. **Add `/api/input/detect`** - Smart input type detection
4. **Standardize input models** - Create unified `UnifiedInputRequest`

### 6.2 Medium Priority

5. **Consistent UI across pages** - Same 5 input methods everywhere
6. **Add drag-and-drop** - Modern file upload experience
7. **Add paste detection** - Auto-detect pasted URLs/content
8. **Add input preview** - Show parsed structure before generation

### 6.3 Low Priority

9. **Add recent inputs** - History of processed sources
10. **Add template gallery** - Visual template browser
11. **Add programmatic API docs** - Swagger/OpenAPI for builders
12. **Add WebSocket wizard** - Real-time wizard interaction

---

## 7. Files to Modify

| File | Changes Needed |
|------|---------------|
| `app/main.py` | Add wizard, yaml, unified endpoints |
| `app/models.py` (new) | Create unified input models |
| `app/templates/home.html` | Add wizard, yaml, programmatic cards |
| `app/templates/create.html` | Unify with create-unified.html |
| `app/templates/components/input-selector.html` | Add all 5 input types |
| `video_gen/shared/models.py` | Add detection confidence field |

---

## 8. Research Artifacts

### Memory Keys Stored:
- `swarm/researcher/input-source-analysis` - Key findings summary

### Related Documentation:
- `/mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen/docs/guides/THREE_INPUT_METHODS_GUIDE.md`
- `/mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen/video_gen/input_adapters/base.py`
- `/mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen/video_gen/shared/models.py`

---

*Research completed by Researcher Agent - November 22, 2025*
