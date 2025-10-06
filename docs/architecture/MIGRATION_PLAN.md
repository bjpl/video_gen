# Migration Plan - Transition to Unified Pipeline

**Version:** 1.0
**Status:** Design Phase
**Last Updated:** 2025-10-04

---

## Table of Contents

1. [Overview](#overview)
2. [Migration Strategy](#migration-strategy)
3. [Phase 1: Foundation](#phase-1-foundation)
4. [Phase 2: Input Consolidation](#phase-2-input-consolidation)
5. [Phase 3: Generation Unification](#phase-3-generation-unification)
6. [Phase 4: Interface Layer](#phase-4-interface-layer)
7. [Phase 5: Cleanup & Deprecation](#phase-5-cleanup--deprecation)
8. [Rollback Plan](#rollback-plan)
9. [Testing Strategy](#testing-strategy)
10. [Success Metrics](#success-metrics)

---

## Overview

### Migration Goals

1. **Zero Downtime**: Old system continues working during migration
2. **Backward Compatibility**: Existing scripts remain functional
3. **Incremental Migration**: Gradual transition with validation at each step
4. **Risk Mitigation**: Easy rollback at any phase
5. **User Communication**: Clear migration guides and deprecation notices

### Migration Principles

- **Build Alongside**: New system built alongside old
- **Dual Operation**: Both systems work in parallel during transition
- **Feature Parity**: New system matches all old features before cutover
- **Gradual Deprecation**: Phased removal with warnings
- **Documentation First**: Update docs before each phase

### Timeline

| Phase | Duration | Effort | Risk |
|-------|----------|--------|------|
| Phase 1: Foundation | 1-2 weeks | 16-24 hours | Low |
| Phase 2: Input Consolidation | 1-2 weeks | 16-24 hours | Low |
| Phase 3: Generation Unification | 2-3 weeks | 24-36 hours | Medium |
| Phase 4: Interface Layer | 1-2 weeks | 12-16 hours | Low |
| Phase 5: Cleanup | 1 week | 8-12 hours | Low |
| **Total** | **6-10 weeks** | **76-112 hours** | **Medium** |

---

## Migration Strategy

### Phased Approach

```
PHASE 1: FOUNDATION (Build Core)
┌─────────────────────────────────────┐
│ • Create package structure          │
│ • Implement PipelineOrchestrator    │
│ • Build StateManager                │
│ • Setup EventBus                    │
│ • Define all contracts              │
│                                     │
│ Status: Old system unchanged        │
│ Risk: None (no changes to existing) │
└─────────────────────────────────────┘
          │
          ▼
PHASE 2: INPUT CONSOLIDATION (Unify Adapters)
┌─────────────────────────────────────┐
│ • Create InputAdapter base          │
│ • Implement DocumentAdapter         │
│ • Implement YouTubeAdapter          │
│ • Implement WizardAdapter           │
│ • Implement YAMLAdapter             │
│                                     │
│ Status: Old + New both work         │
│ Risk: Low (parallel systems)        │
└─────────────────────────────────────┘
          │
          ▼
PHASE 3: GENERATION UNIFICATION (Merge Generators)
┌─────────────────────────────────────┐
│ • Unify audio generators            │
│ • Unify video generators            │
│ • Merge script generators           │
│ • Consolidate parsing               │
│                                     │
│ Status: New becomes preferred       │
│ Risk: Medium (functionality changes)│
└─────────────────────────────────────┘
          │
          ▼
PHASE 4: INTERFACE LAYER (User-Facing)
┌─────────────────────────────────────┐
│ • Build unified CLI                 │
│ • Refactor Web UI                   │
│ • Create Python API                 │
│ • Add resume capability             │
│                                     │
│ Status: New is default              │
│ Risk: Low (well-tested core)        │
└─────────────────────────────────────┘
          │
          ▼
PHASE 5: CLEANUP & DEPRECATION (Remove Old)
┌─────────────────────────────────────┐
│ • Deprecate old scripts             │
│ • Update documentation              │
│ • Remove duplicate code             │
│ • Archive legacy                    │
│                                     │
│ Status: New system only             │
│ Risk: Low (migration complete)      │
└─────────────────────────────────────┘
```

### Feature Flags

Use feature flags for gradual rollout:

```python
# config.py
class FeatureFlags:
    # Phase 2
    USE_NEW_INPUT_ADAPTERS = os.getenv(
        "USE_NEW_INPUT_ADAPTERS",
        "false"
    ).lower() == "true"

    # Phase 3
    USE_NEW_GENERATORS = os.getenv(
        "USE_NEW_GENERATORS",
        "false"
    ).lower() == "true"

    # Phase 4
    USE_NEW_CLI = os.getenv(
        "USE_NEW_CLI",
        "false"
    ).lower() == "true"

# Usage in code
if FeatureFlags.USE_NEW_INPUT_ADAPTERS:
    adapter = DocumentAdapter()  # New
else:
    adapter = legacy_document_parser()  # Old
```

---

## Phase 1: Foundation

### Objectives

- Create core pipeline infrastructure
- No changes to existing functionality
- Foundation for all future work

### Tasks

#### 1.1 Create Package Structure

```bash
# Create new package
mkdir -p video_gen/{pipeline,input_adapters,stages,shared}

# Directory structure
video_gen/
├── __init__.py
├── pipeline/
│   ├── __init__.py
│   ├── orchestrator.py
│   ├── state_manager.py
│   └── events.py
├── input_adapters/
│   ├── __init__.py
│   └── base.py
├── stages/
│   ├── __init__.py
│   ├── base.py
│   ├── input_stage.py
│   ├── parsing_stage.py
│   ├── script_gen_stage.py
│   ├── audio_gen_stage.py
│   ├── video_gen_stage.py
│   └── output_stage.py
├── shared/
│   ├── __init__.py
│   ├── models.py
│   ├── config.py
│   ├── errors.py
│   └── utils.py
└── storage/
    ├── __init__.py
    ├── base.py
    ├── json_backend.py
    └── sqlite_backend.py
```

#### 1.2 Implement Core Components

**PipelineOrchestrator** (`video_gen/pipeline/orchestrator.py`):
```python
# See PIPELINE_ARCHITECTURE.md for full implementation
class PipelineOrchestrator:
    def __init__(self, state_manager, event_bus, config):
        self.state = state_manager
        self.events = event_bus
        self.config = config
        self.stages = []

    async def execute(self, input_config):
        # Implementation
        pass
```

**StateManager** (`video_gen/pipeline/state_manager.py`):
```python
# See STATE_MANAGEMENT_SPEC.md for full implementation
class StateManager:
    def __init__(self, storage_backend):
        self.storage = storage_backend

    async def create_task(self, input_config):
        # Implementation
        pass
```

**EventBus** (`video_gen/pipeline/events.py`):
```python
# See PIPELINE_ARCHITECTURE.md for full implementation
class EventBus:
    def __init__(self):
        self.subscribers = {}

    def emit(self, event):
        # Implementation
        pass
```

#### 1.3 Define Data Models

**Models** (`video_gen/shared/models.py`):
```python
# See API_CONTRACTS.md for all models
from pydantic import BaseModel

class InputConfig(BaseModel):
    # Full implementation
    pass

class VideoSetConfig(BaseModel):
    # Full implementation
    pass

# ... etc
```

#### 1.4 Write Foundation Tests

```python
# tests/test_orchestrator.py
import pytest
from video_gen.pipeline import PipelineOrchestrator

@pytest.mark.asyncio
async def test_orchestrator_initialization():
    orchestrator = PipelineOrchestrator(...)
    assert orchestrator is not None

@pytest.mark.asyncio
async def test_orchestrator_execute():
    # Test basic execution
    pass
```

### Deliverables

- [ ] Package structure created
- [ ] Core classes implemented
- [ ] Data models defined
- [ ] Unit tests written (80% coverage)
- [ ] Documentation updated

### Success Criteria

- All tests pass
- No impact on existing scripts
- Code review completed
- Documentation reviewed

---

## Phase 2: Input Consolidation

### Objectives

- Unify all input methods
- Create adapter pattern
- Maintain backward compatibility

### Tasks

#### 2.1 Create Base Adapter

```python
# video_gen/input_adapters/base.py
from abc import ABC, abstractmethod
from video_gen.shared.models import VideoSetConfig

class InputAdapter(ABC):
    @abstractmethod
    async def adapt(self, raw_input) -> VideoSetConfig:
        pass

    @abstractmethod
    def supports(self, input_type: str) -> bool:
        pass
```

#### 2.2 Implement Document Adapter

```python
# video_gen/input_adapters/document.py
from .base import InputAdapter
from scripts.document_to_programmatic import parse_document  # Reuse!

class DocumentAdapter(InputAdapter):
    async def adapt(self, raw_input: DocumentInput) -> VideoSetConfig:
        # Wrap existing document parser
        parsed = parse_document(raw_input.path)

        # Convert to VideoSetConfig
        return VideoSetConfig(
            set_id=...,
            videos=...,
            # ...
        )

    def supports(self, input_type: str) -> bool:
        return input_type == "document"
```

#### 2.3 Implement YouTube Adapter

```python
# video_gen/input_adapters/youtube.py
from .base import InputAdapter
from scripts.youtube_to_programmatic import extract_from_youtube  # Reuse!

class YouTubeAdapter(InputAdapter):
    async def adapt(self, raw_input: YouTubeInput) -> VideoSetConfig:
        # Wrap existing YouTube parser
        extracted = extract_from_youtube(raw_input.url)

        # Convert to VideoSetConfig
        return VideoSetConfig(...)

    def supports(self, input_type: str) -> bool:
        return input_type == "youtube"
```

#### 2.4 Implement Wizard Adapter

```python
# video_gen/input_adapters/wizard.py
from .base import InputAdapter
from scripts.generate_script_wizard_set_aware import run_wizard  # Reuse!

class WizardAdapter(InputAdapter):
    async def adapt(self, raw_input: WizardInput) -> VideoSetConfig:
        # Wrap existing wizard
        result = run_wizard(raw_input.responses)

        # Convert to VideoSetConfig
        return VideoSetConfig(...)

    def supports(self, input_type: str) -> bool:
        return input_type == "wizard"
```

#### 2.5 Implement YAML Adapter

```python
# video_gen/input_adapters/yaml_file.py
from .base import InputAdapter
import yaml

class YAMLAdapter(InputAdapter):
    async def adapt(self, raw_input: YAMLInput) -> VideoSetConfig:
        # Load YAML
        with open(raw_input.path) as f:
            data = yaml.safe_load(f)

        # Convert to VideoSetConfig
        return VideoSetConfig(**data)

    def supports(self, input_type: str) -> bool:
        return input_type == "yaml"
```

#### 2.6 Create Adapter Registry

```python
# video_gen/input_adapters/__init__.py
from .document import DocumentAdapter
from .youtube import YouTubeAdapter
from .wizard import WizardAdapter
from .yaml_file import YAMLAdapter

class AdapterRegistry:
    def __init__(self):
        self.adapters = {
            "document": DocumentAdapter(),
            "youtube": YouTubeAdapter(),
            "wizard": WizardAdapter(),
            "yaml": YAMLAdapter()
        }

    def get_adapter(self, input_type: str):
        if input_type not in self.adapters:
            raise ValueError(f"Unsupported input type: {input_type}")
        return self.adapters[input_type]
```

### Migration Strategy for Phase 2

**Week 1: Build**
- Implement all adapters
- Write comprehensive tests
- Add feature flag

**Week 2: Validate**
- Run parallel tests (old vs new)
- Compare outputs
- Fix discrepancies

**Rollout:**
```python
# In CLI/Web UI:
if FeatureFlags.USE_NEW_INPUT_ADAPTERS:
    # Use new adapter
    registry = AdapterRegistry()
    adapter = registry.get_adapter(input_type)
    video_set = await adapter.adapt(raw_input)
else:
    # Use old scripts (unchanged)
    if input_type == "document":
        from scripts.document_to_programmatic import parse_document
        result = parse_document(...)
    # ... etc
```

### Deliverables

- [ ] All adapters implemented
- [ ] Adapter registry created
- [ ] Integration tests written
- [ ] Parallel validation completed
- [ ] Feature flag added

### Success Criteria

- New adapters produce identical output to old scripts
- All tests pass (old and new)
- Performance is equivalent or better
- Feature flag tested in both modes

---

## Phase 3: Generation Unification

### Objectives

- Merge duplicate audio generators
- Merge duplicate video generators
- Unify script generation
- Single code path for all video types

### Tasks

#### 3.1 Unify Audio Generation

**Current State:**
- `generate_all_videos_unified_v2.py` (single videos)
- `generate_video_set.py` (video sets)

**New Implementation:**
```python
# video_gen/stages/audio_gen_stage.py
from scripts.unified_video_system import UnifiedScene  # Reuse!
import edge_tts

class AudioGenerationStage(Stage):
    async def execute(self, input: AudioGenStageInput) -> AudioGenStageOutput:
        video_script = input.data
        audio_files = []

        for scene in video_script.scenes:
            # Generate TTS (reuse existing logic)
            audio_file = await self._generate_tts(
                scene.narration,
                scene.voice
            )

            audio_files.append(SceneAudio(
                scene_id=scene.scene_id,
                audio_file=audio_file,
                actual_duration=self._get_duration(audio_file),
                word_count=scene.word_count,
                voice_used=scene.voice
            ))

        return AudioGenStageOutput(
            data=AudioAssets(
                video_id=video_script.video_id,
                scene_audios=audio_files,
                # ...
            )
        )

    async def _generate_tts(self, text: str, voice: str) -> str:
        # Reuse existing TTS logic from unified_video_system
        # ...
        pass
```

**Migration:**
1. Extract TTS logic to shared module
2. Create unified AudioGenerationStage
3. Add feature flag
4. Run parallel tests
5. Deprecate old scripts

#### 3.2 Unify Video Generation

**Current State:**
- `generate_videos_from_timings_v3_simple.py` (basic)
- `generate_videos_from_set.py` (sets)

**New Implementation:**
```python
# video_gen/stages/video_gen_stage.py
from scripts.unified_video_system import UnifiedVideo  # Reuse!

class VideoGenerationStage(Stage):
    async def execute(self, input: VideoGenStageInput) -> VideoGenStageOutput:
        audio_assets = input.audio_assets
        video_script = input.video_script
        rendered_videos = []

        for scene_audio in audio_assets.scene_audios:
            # Find corresponding scene
            scene = next(
                s for s in video_script.scenes
                if s.scene_id == scene_audio.scene_id
            )

            # Render scene (reuse existing rendering logic)
            video_file = await self._render_scene(
                scene,
                scene_audio
            )

            rendered_videos.append(RenderedVideo(
                video_id=scene.scene_id,
                video_file=video_file,
                duration=scene_audio.actual_duration,
                # ...
            ))

        return VideoGenStageOutput(
            data=VideoAssets(
                videos=rendered_videos,
                # ...
            )
        )

    async def _render_scene(self, scene, audio):
        # Reuse existing rendering from unified_video_system
        # ...
        pass
```

**Migration:**
1. Extract rendering logic to shared module
2. Create unified VideoGenerationStage
3. Add feature flag
4. Run parallel tests
5. Deprecate old scripts

#### 3.3 Unify Script Generation

**Current State:**
- `generate_script_from_yaml.py`
- `generate_script_from_document.py`
- AI-enhanced vs. template-based

**New Implementation:**
```python
# video_gen/stages/script_gen_stage.py
class ScriptGenerationStage(Stage):
    def __init__(self, ai_client=None):
        self.ai_client = ai_client  # Optional

    async def execute(self, input: ScriptGenStageInput) -> ScriptGenStageOutput:
        parsed_content = input.data
        scripted_scenes = []

        for section in parsed_content.sections:
            # Generate narration
            if self.ai_client and input.config.get("use_ai"):
                narration = await self._generate_ai_narration(section)
            else:
                narration = self._generate_template_narration(section)

            scripted_scenes.append(ScriptedScene(
                scene_id=section.section_id,
                narration=narration,
                # ...
            ))

        return ScriptGenStageOutput(
            data=VideoScript(
                scenes=scripted_scenes,
                # ...
            )
        )
```

### Deliverables

- [ ] Unified audio generator
- [ ] Unified video generator
- [ ] Unified script generator
- [ ] Shared rendering/TTS modules
- [ ] Migration tests

### Success Criteria

- Single code path for all video types
- Feature parity with old scripts
- Performance equivalent or better
- All tests pass

---

## Phase 4: Interface Layer

### Objectives

- Create unified CLI
- Refactor Web UI
- Build Python API
- Add resume capability

### Tasks

#### 4.1 Build Unified CLI

```python
# cli/video_gen_cli.py
import argparse
from video_gen.pipeline import PipelineOrchestrator
from video_gen.shared.models import InputConfig

def main():
    parser = argparse.ArgumentParser(
        description="Video Generation Pipeline"
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command")

    # create command
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument(
        "--from",
        dest="source",
        required=True,
        help="Input source (document:path, youtube:url, etc.)"
    )
    create_parser.add_argument("--output", default="./videos")
    create_parser.add_argument("--color", default="blue")
    create_parser.add_argument("--voice", default="male")
    create_parser.add_argument("--resume", help="Resume task ID")

    # resume command
    resume_parser = subparsers.add_parser("resume")
    resume_parser.add_argument("task_id")

    # status command
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("task_id")

    args = parser.parse_args()

    if args.command == "create":
        # Parse source
        source_type, source_value = args.source.split(":", 1)

        # Create input config
        input_config = InputConfig(
            source_type=source_type,
            source_data={"path": source_value},  # Simplified
            accent_color=args.color,
            voice=args.voice,
            output_dir=args.output
        )

        # Execute
        orchestrator = PipelineOrchestrator(...)
        result = asyncio.run(
            orchestrator.execute(
                input_config,
                resume_from=args.resume
            )
        )

        print(f"✅ Videos created: {result.videos}")

    elif args.command == "resume":
        # Resume task
        orchestrator = PipelineOrchestrator(...)
        result = asyncio.run(
            orchestrator.execute(resume_from=args.task_id)
        )

    elif args.command == "status":
        # Get status
        state_manager = StateManager(...)
        status = asyncio.run(
            state_manager.get_task_status(args.task_id)
        )
        print(json.dumps(status, indent=2))

if __name__ == "__main__":
    main()
```

**Install as command:**
```bash
# setup.py
setup(
    name="video-gen",
    entry_points={
        "console_scripts": [
            "video-gen=cli.video_gen_cli:main",
        ],
    },
)

# Install
pip install -e .

# Use
video-gen create --from document:README.md --output ./videos
```

#### 4.2 Refactor Web UI

```python
# app/main.py (refactored)
from fastapi import FastAPI
from video_gen.pipeline import PipelineOrchestrator
from video_gen.shared.models import InputConfig

app = FastAPI()

@app.post("/api/create")
async def create_video(request: ParseRequest):
    # Convert to InputConfig
    input_config = InputConfig(
        source_type=request.input_type,
        source_data=request.model_dump(exclude_none=True),
        accent_color=request.accent_color,
        voice=request.voice
    )

    # Execute pipeline (async)
    orchestrator = get_orchestrator()
    task = await orchestrator.create_task_async(input_config)

    return {"task_id": task.id}

@app.get("/api/status/{task_id}")
async def get_status(task_id: str):
    state_manager = get_state_manager()
    status = await state_manager.get_task_status(task_id)
    return status

@app.get("/api/progress/{task_id}")
async def stream_progress(task_id: str):
    # Server-Sent Events for real-time progress
    async def event_generator():
        event_bus = get_event_bus()

        async def on_progress(event):
            if event.task_id == task_id:
                yield f"data: {json.dumps(event.__dict__)}\n\n"

        event_bus.subscribe(ProgressEvent, on_progress)

        # Keep connection open
        while True:
            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())
```

#### 4.3 Create Python API

```python
# video_gen/__init__.py
from .pipeline import PipelineOrchestrator, Pipeline
from .shared.models import InputConfig

__version__ = "2.0.0"
__all__ = ["Pipeline", "InputConfig"]

# Convenience API
class Pipeline:
    """High-level Python API"""

    @staticmethod
    async def create(
        source: str,
        output_dir: str = "./videos",
        **kwargs
    ):
        """
        Create video from source.

        Args:
            source: Input source (file path, URL, etc.)
            output_dir: Output directory
            **kwargs: Additional options (color, voice, etc.)

        Returns:
            PipelineResult

        Example:
            result = await Pipeline.create(
                "README.md",
                output_dir="./videos",
                color="blue",
                voice="male"
            )
        """
        # Auto-detect source type
        source_type = Pipeline._detect_source_type(source)

        # Create input config
        input_config = InputConfig(
            source_type=source_type,
            source_data={"path": source},
            output_dir=output_dir,
            **kwargs
        )

        # Execute
        orchestrator = PipelineOrchestrator(...)
        return await orchestrator.execute(input_config)

    @staticmethod
    def _detect_source_type(source: str) -> str:
        """Auto-detect source type"""
        if source.startswith("http"):
            if "youtube.com" in source:
                return "youtube"
            return "document"  # Remote doc
        elif source.endswith(".yaml"):
            return "yaml"
        else:
            return "document"
```

**Usage:**
```python
# Simple usage
from video_gen import Pipeline

result = await Pipeline.create(
    "README.md",
    output_dir="./videos",
    color="blue"
)

print(f"Video: {result.videos[0]}")
```

### Deliverables

- [ ] Unified CLI implemented
- [ ] Web UI refactored
- [ ] Python API created
- [ ] Resume functionality working
- [ ] User documentation updated

### Success Criteria

- One-command video creation works
- Web UI uses new pipeline
- Python API is intuitive
- Resume works reliably
- Documentation is clear

---

## Phase 5: Cleanup & Deprecation

### Objectives

- Remove duplicate code
- Deprecate old scripts
- Archive legacy code
- Final documentation

### Tasks

#### 5.1 Deprecate Old Scripts

Add deprecation warnings:

```python
# scripts/generate_all_videos_unified_v2.py
import warnings

warnings.warn(
    "This script is deprecated. Use 'video-gen create' instead.\n"
    "See: https://docs.example.com/migration-guide",
    DeprecationWarning,
    stacklevel=2
)

# Rest of old code...
```

Create deprecation mapping:

```python
# DEPRECATION.md
| Old Script | New Alternative | Deprecated | Removed |
|------------|----------------|------------|---------|
| `generate_all_videos_unified_v2.py` | `video-gen create` | v2.0 | v3.0 |
| `generate_video_set.py` | `video-gen create` | v2.0 | v3.0 |
| `generate_videos_from_timings_v3_simple.py` | Automatic (pipeline) | v2.0 | v3.0 |
| `document_to_programmatic.py` | `video-gen create --from document:` | v2.0 | v3.0 |
```

#### 5.2 Archive Legacy Code

```bash
# Move old scripts to archive
mkdir -p archive/legacy_scripts
mv scripts/generate_all_videos_unified_v2.py archive/legacy_scripts/
mv scripts/generate_video_set.py archive/legacy_scripts/
# ... etc

# Update .gitignore
echo "archive/" >> .gitignore
```

#### 5.3 Remove Duplicate Code

```bash
# Identify duplicates
# Run code analysis tool
ruff check --select=DUP .

# Remove after verification
rm scripts/generate_videos_from_set.py  # Merged into pipeline
rm scripts/generate_script_wizard.py    # Superseded by wizard adapter
# ... etc
```

#### 5.4 Update All Documentation

**README.md:**
```markdown
# Video Generation System v2.0

## Quick Start

```bash
# One command to create video
video-gen create --from README.md --output ./videos
```

## Migration from v1.x

See [MIGRATION_GUIDE.md](./MIGRATION_GUIDE.md) for upgrading from v1.x.

**Old way (deprecated):**
```bash
python scripts/create_video.py --document README.md
python scripts/generate_script_from_yaml.py ...
python scripts/generate_all_videos_unified_v2.py
python scripts/generate_videos_from_timings_v3_simple.py
```

**New way:**
```bash
video-gen create --from README.md
```
```

**MIGRATION_GUIDE.md:**
```markdown
# Migration Guide: v1.x → v2.0

## Overview

Version 2.0 introduces a unified pipeline system...

## Breaking Changes

1. **CLI Changes**
   - Old: `python scripts/create_video.py --document README.md`
   - New: `video-gen create --from document:README.md`

2. **Python API Changes**
   - Old: Import individual scripts
   - New: `from video_gen import Pipeline`

## Migration Steps

### Step 1: Install v2.0
```bash
pip install --upgrade video-gen
```

### Step 2: Update Commands
[Detailed command mapping...]

### Step 3: Update Scripts
[Code examples...]

## Support

- Slack: #video-gen-support
- Issues: https://github.com/.../issues
- Docs: https://docs.example.com
```

### Deliverables

- [ ] Deprecation warnings added
- [ ] Legacy code archived
- [ ] Duplicate code removed
- [ ] All documentation updated
- [ ] Migration guide created

### Success Criteria

- No duplicate code remains
- All docs reflect new system
- Migration guide is comprehensive
- Old scripts warn users

---

## Rollback Plan

### Rollback Triggers

Rollback if:
- Critical bugs in new system
- Performance degradation > 20%
- Data loss or corruption
- User adoption < 30% after 4 weeks

### Rollback Procedure

**Phase 2-3 Rollback:**
```bash
# Disable feature flags
export USE_NEW_INPUT_ADAPTERS=false
export USE_NEW_GENERATORS=false

# Restart services
systemctl restart video-gen-web

# Verify old system works
python scripts/generate_all_videos_unified_v2.py
```

**Phase 4 Rollback:**
```bash
# Uninstall new CLI
pip uninstall video-gen

# Restore old scripts from git
git checkout v1.9.0 -- scripts/

# Update documentation
git checkout v1.9.0 -- README.md
```

**Phase 5 Rollback:**
```bash
# Restore from archive
cp -r archive/legacy_scripts/* scripts/

# Re-enable old system
git revert <migration-commit>
```

### Rollback Validation

After rollback:
1. Run full test suite
2. Verify all old scripts work
3. Check user workflows
4. Update documentation
5. Communicate to users

---

## Testing Strategy

### Test Phases

#### Unit Tests (Each Phase)

```python
# tests/test_adapters.py
@pytest.mark.parametrize("input_type,adapter_class", [
    ("document", DocumentAdapter),
    ("youtube", YouTubeAdapter),
    ("wizard", WizardAdapter),
])
async def test_adapter(input_type, adapter_class):
    adapter = adapter_class()
    result = await adapter.adapt(sample_input)
    assert isinstance(result, VideoSetConfig)
```

#### Integration Tests (Phase 3+)

```python
# tests/test_pipeline.py
@pytest.mark.asyncio
async def test_full_pipeline():
    """Test complete pipeline execution"""
    orchestrator = PipelineOrchestrator(...)

    result = await orchestrator.execute(
        InputConfig(
            source_type="document",
            source_data={"path": "test.md"}
        )
    )

    assert result.status == "success"
    assert len(result.videos) > 0
    assert Path(result.videos[0]).exists()
```

#### Parallel Validation Tests

```python
# tests/test_migration.py
@pytest.mark.asyncio
async def test_old_vs_new_output():
    """Verify new system produces same output as old"""

    # Run old system
    old_result = run_old_system("test.md")

    # Run new system
    new_result = await run_new_system("test.md")

    # Compare outputs
    assert_videos_equivalent(old_result, new_result)
```

#### Performance Tests

```python
# tests/test_performance.py
@pytest.mark.benchmark
async def test_pipeline_performance():
    """Ensure new system is as fast as old"""

    start = time.time()
    result = await orchestrator.execute(input_config)
    duration = time.time() - start

    # Should be within 10% of old system
    assert duration < OLD_SYSTEM_BASELINE * 1.1
```

### Test Coverage Goals

| Component | Target Coverage |
|-----------|----------------|
| Core Pipeline | 90% |
| Adapters | 85% |
| Stages | 90% |
| State Management | 95% |
| Error Handling | 100% |

---

## Success Metrics

### Technical Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Code Reduction** | 40-50% | Lines of code |
| **Test Coverage** | > 85% | pytest-cov |
| **Performance** | ±10% of baseline | Execution time |
| **Bug Rate** | < 5 critical bugs | Issue tracker |
| **Uptime** | > 99.5% | Monitoring |

### User Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Adoption Rate** | > 70% in 8 weeks | Usage analytics |
| **User Satisfaction** | > 4.0/5.0 | User surveys |
| **Support Tickets** | < 20% increase | Support system |
| **Documentation Quality** | > 4.5/5.0 | User feedback |

### Process Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Migration Completion** | 6-10 weeks | Timeline |
| **Rollbacks** | 0 | Incident log |
| **Breaking Changes** | 0 unplanned | Change log |
| **Team Velocity** | Maintained | Sprint metrics |

---

## Communication Plan

### Stakeholder Communication

#### Week 0 (Before Migration)

**To: All Users**
```
Subject: Video Generation System v2.0 Coming Soon

We're excited to announce v2.0 of the video generation system!

What's New:
- One-command video creation
- Automatic resume on failures
- Real-time progress tracking
- 50%+ faster execution

Migration will begin [DATE] and complete by [DATE].

What You Need to Do:
- Nothing during Phase 1-2 (no changes)
- Update CLI in Phase 4 (migration guide provided)
- Old scripts will continue working with deprecation warnings

Timeline: [Link to roadmap]
Questions: #video-gen-migration
```

#### Each Phase

**Phase Start:**
- Announce phase beginning
- Link to documentation
- Explain what's changing

**Phase End:**
- Announce phase completion
- Share results/metrics
- Preview next phase

#### Post-Migration

**To: All Users**
```
Subject: Video Generation v2.0 Migration Complete!

🎉 Migration to v2.0 is complete!

Results:
- 47% code reduction
- 65% faster video creation
- 92% user adoption
- Zero downtime

What's Next:
- Old scripts deprecated (will be removed in v3.0)
- New features coming: [...]
- Documentation: [link]

Thanks for your patience during the migration!
```

---

## Appendix: Script Mapping

### Complete Old → New Mapping

| Old Script | Function | New Alternative |
|------------|----------|-----------------|
| `create_video.py` | Parse document | `video-gen create --from document:PATH` |
| `generate_script_from_document.py` | Generate script | Automatic (pipeline) |
| `generate_script_from_youtube.py` | YouTube script | `video-gen create --from youtube:URL` |
| `generate_script_from_yaml.py` | YAML script | `video-gen create --from yaml:PATH` |
| `generate_script_wizard.py` | Interactive | `video-gen create --from wizard` |
| `generate_script_wizard_set_aware.py` | Interactive (sets) | `video-gen create --from wizard` |
| `document_to_programmatic.py` | Doc parsing | DocumentAdapter (internal) |
| `youtube_to_programmatic.py` | YouTube parsing | YouTubeAdapter (internal) |
| `python_set_builder.py` | Programmatic API | `from video_gen import Pipeline` |
| `generate_all_videos_unified_v2.py` | Audio gen | Automatic (pipeline) |
| `generate_video_set.py` | Audio gen (sets) | Automatic (pipeline) |
| `generate_videos_from_timings_v3_simple.py` | Video gen | Automatic (pipeline) |
| `generate_videos_from_set.py` | Video gen (sets) | Automatic (pipeline) |
| `multilingual_builder.py` | Multilingual | `video-gen create --languages en,es,...` |

---

**Document Status:** Ready for Implementation
**Dependencies:** All architecture documents
**Next Steps:** Begin Phase 1
