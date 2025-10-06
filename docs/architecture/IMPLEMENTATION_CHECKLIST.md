# Implementation Checklist - Unified Pipeline System

**Quick reference guide for implementing the architecture**
**Use this during Sprint planning and implementation**

---

## 📋 Sprint 1: Foundation (Week 1-2)

### Setup & Structure

- [ ] **Create package structure**
  ```bash
  mkdir -p video_gen/{pipeline,input_adapters,stages,shared,storage}
  touch video_gen/__init__.py
  touch video_gen/pipeline/{__init__.py,orchestrator.py,state_manager.py,events.py}
  touch video_gen/stages/{__init__.py,base.py}
  touch video_gen/shared/{__init__.py,models.py,config.py,errors.py}
  ```

- [ ] **Setup development environment**
  ```bash
  pip install pydantic aiofiles pytest pytest-asyncio pytest-cov
  ```

### Core Implementation

- [ ] **Implement data models** (`video_gen/shared/models.py`)
  - [ ] `InputConfig`
  - [ ] `VideoSetConfig`
  - [ ] `VideoConfig`
  - [ ] `SceneConfig`
  - [ ] `ParsedContent`
  - [ ] `VideoScript`
  - [ ] `AudioAssets`
  - [ ] `VideoAssets`
  - [ ] `PipelineResult`

- [ ] **Implement Stage base class** (`video_gen/stages/base.py`)
  - [ ] `Stage` ABC with `execute()`, `validate()`, `estimate_duration()`
  - [ ] `StageInput` and `StageOutput` models
  - [ ] `ValidationResult` model

- [ ] **Implement StateManager** (`video_gen/pipeline/state_manager.py`)
  - [ ] Task state model (`Task`, `TaskStatus`, `StageResult`)
  - [ ] JSON storage backend
  - [ ] Basic CRUD operations
  - [ ] Test persistence

- [ ] **Implement EventBus** (`video_gen/pipeline/events.py`)
  - [ ] Event base class
  - [ ] Subscribe/emit methods
  - [ ] Event types: `ProgressEvent`, `StageStartEvent`, `StageCompleteEvent`

- [ ] **Implement PipelineOrchestrator** (`video_gen/pipeline/orchestrator.py`)
  - [ ] Basic execute flow
  - [ ] Stage registration
  - [ ] State management integration
  - [ ] Event emission

### Testing

- [ ] **Write foundation tests**
  ```python
  tests/
  ├── test_models.py (data validation)
  ├── test_state_manager.py (persistence)
  ├── test_events.py (pub/sub)
  └── test_orchestrator.py (basic flow)
  ```

- [ ] **Target: 80%+ coverage**
  ```bash
  pytest --cov=video_gen tests/
  ```

### Deliverables

- [ ] Package structure exists
- [ ] All core classes implemented
- [ ] Tests pass with 80%+ coverage
- [ ] No changes to existing scripts
- [ ] Documentation updated

---

## 📋 Sprint 2: Input Consolidation (Week 3-4)

### Adapter Base

- [ ] **Implement InputAdapter base** (`video_gen/input_adapters/base.py`)
  ```python
  class InputAdapter(ABC):
      @abstractmethod
      async def adapt(self, raw_input) -> VideoSetConfig: pass

      @abstractmethod
      def supports(self, input_type: str) -> bool: pass
  ```

### Individual Adapters

- [ ] **DocumentAdapter** (`video_gen/input_adapters/document.py`)
  - [ ] Wrap `scripts/document_to_programmatic.py`
  - [ ] Support MD, TXT, PDF
  - [ ] Extract sections
  - [ ] Generate VideoSetConfig
  - [ ] Test with sample documents

- [ ] **YouTubeAdapter** (`video_gen/input_adapters/youtube.py`)
  - [ ] Wrap `scripts/youtube_to_programmatic.py`
  - [ ] Download transcript
  - [ ] Extract chapters
  - [ ] Generate VideoSetConfig
  - [ ] Test with sample videos

- [ ] **WizardAdapter** (`video_gen/input_adapters/wizard.py`)
  - [ ] Wrap `scripts/generate_script_wizard_set_aware.py`
  - [ ] Handle wizard responses
  - [ ] Apply templates
  - [ ] Generate VideoSetConfig
  - [ ] Test interactive flow

- [ ] **YAMLAdapter** (`video_gen/input_adapters/yaml_file.py`)
  - [ ] Load YAML files
  - [ ] Validate structure
  - [ ] Convert to VideoSetConfig
  - [ ] Test with existing YAMLs

- [ ] **ProgrammaticAdapter** (`video_gen/input_adapters/programmatic.py`)
  - [ ] Accept Python objects
  - [ ] Validate structure
  - [ ] Convert to VideoSetConfig
  - [ ] Test with `python_set_builder`

### Integration

- [ ] **Create AdapterRegistry** (`video_gen/input_adapters/__init__.py`)
  ```python
  registry = AdapterRegistry()
  adapter = registry.get_adapter("document")
  result = await adapter.adapt(input)
  ```

- [ ] **Implement InputStage** (`video_gen/stages/input_stage.py`)
  - [ ] Use AdapterRegistry
  - [ ] Handle all input types
  - [ ] Return VideoSetConfig

### Testing

- [ ] **Parallel validation tests**
  ```python
  # Compare old vs new outputs
  old_result = run_old_document_parser("test.md")
  new_result = await DocumentAdapter().adapt(DocumentInput(path="test.md"))
  assert_equivalent(old_result, new_result)
  ```

- [ ] **Integration tests**
  - [ ] Test each adapter
  - [ ] Test registry
  - [ ] Test InputStage
  - [ ] Test with real files

### Feature Flag

- [ ] **Add feature flag** (`video_gen/shared/config.py`)
  ```python
  USE_NEW_INPUT_ADAPTERS = os.getenv("USE_NEW_INPUT_ADAPTERS", "false") == "true"
  ```

- [ ] **Update existing code to check flag**

### Deliverables

- [ ] All 5 adapters implemented
- [ ] AdapterRegistry working
- [ ] InputStage complete
- [ ] Parallel validation passed
- [ ] Tests pass with 85%+ coverage
- [ ] Feature flag tested

---

## 📋 Sprint 3: Generation Unification (Week 5-7)

### Shared Modules

- [ ] **Extract TTS logic** (`video_gen/shared/tts.py`)
  - [ ] Extract from `unified_video_system.py`
  - [ ] Support all voices
  - [ ] Return audio file + duration

- [ ] **Extract rendering logic** (`video_gen/shared/rendering.py`)
  - [ ] Extract from `unified_video_system.py`
  - [ ] Scene rendering functions
  - [ ] Transition logic
  - [ ] FFmpeg encoding

### Stage Implementation

- [ ] **ParsingStage** (`video_gen/stages/parsing_stage.py`)
  - [ ] Extract sections from VideoSetConfig
  - [ ] Identify structure
  - [ ] Return ParsedContent
  - [ ] Validate input

- [ ] **ScriptGenerationStage** (`video_gen/stages/script_gen_stage.py`)
  - [ ] Generate narration for each scene
  - [ ] Support template-based
  - [ ] Support AI-enhanced (optional)
  - [ ] Return VideoScript
  - [ ] Validate timing

- [ ] **AudioGenerationStage** (`video_gen/stages/audio_gen_stage.py`)
  - [ ] Use shared TTS module
  - [ ] Generate audio for all scenes
  - [ ] Calculate actual durations
  - [ ] Create timing reports
  - [ ] Return AudioAssets

- [ ] **VideoGenerationStage** (`video_gen/stages/video_gen_stage.py`)
  - [ ] Use shared rendering module
  - [ ] Render keyframes
  - [ ] Apply transitions
  - [ ] Encode with FFmpeg
  - [ ] Mux audio
  - [ ] Return VideoAssets

- [ ] **OutputStage** (`video_gen/stages/output_stage.py`)
  - [ ] Organize output files
  - [ ] Generate metadata
  - [ ] Return PipelineResult

### Error Handling

- [ ] **Implement retry logic** (`video_gen/pipeline/retry.py`)
  ```python
  class RetryPolicy:
      async def execute(self, func, args):
          # Exponential backoff
          pass
  ```

- [ ] **Add error types** (`video_gen/shared/errors.py`)
  - [ ] `StageError`
  - [ ] `AudioGenError`
  - [ ] `VideoGenError`
  - [ ] `RetryExhaustedError`

### Integration

- [ ] **Register all stages in orchestrator**
  ```python
  orchestrator.register_stage(InputStage(...))
  orchestrator.register_stage(ParsingStage(...))
  orchestrator.register_stage(ScriptGenerationStage(...))
  orchestrator.register_stage(AudioGenerationStage(...))
  orchestrator.register_stage(VideoGenerationStage(...))
  orchestrator.register_stage(OutputStage(...))
  ```

### Testing

- [ ] **End-to-end tests**
  ```python
  async def test_complete_pipeline():
      result = await orchestrator.execute(InputConfig(
          source_type="document",
          source_data={"path": "test.md"}
      ))
      assert result.status == "success"
      assert len(result.videos) > 0
  ```

- [ ] **Performance tests**
  - [ ] Benchmark against old system
  - [ ] Measure memory usage
  - [ ] Verify speed

### Feature Flag

- [ ] **Add feature flag**
  ```python
  USE_NEW_GENERATORS = os.getenv("USE_NEW_GENERATORS", "false") == "true"
  ```

### Deliverables

- [ ] All 6 stages implemented
- [ ] Shared TTS/rendering modules
- [ ] Retry logic working
- [ ] End-to-end pipeline works
- [ ] Tests pass with 90%+ coverage
- [ ] Performance ≥ old system

---

## 📋 Sprint 4: Interface Layer (Week 8-9)

### CLI

- [ ] **Implement CLI** (`cli/video_gen_cli.py`)
  ```python
  # Commands:
  # video-gen create --from <source>
  # video-gen resume <task_id>
  # video-gen status <task_id>
  # video-gen list
  ```

- [ ] **Setup entry point** (`setup.py`)
  ```python
  entry_points={
      "console_scripts": [
          "video-gen=cli.video_gen_cli:main",
      ],
  }
  ```

- [ ] **Test CLI**
  ```bash
  video-gen create --from README.md --output ./videos
  video-gen status <task_id>
  ```

### Web UI Refactor

- [ ] **Update FastAPI endpoints** (`app/main.py`)
  ```python
  @app.post("/api/create")
  async def create_video(request: ParseRequest):
      orchestrator = get_orchestrator()
      result = await orchestrator.execute(...)
      return {"task_id": result.task_id}
  ```

- [ ] **Add SSE endpoint for progress**
  ```python
  @app.get("/api/progress/{task_id}")
  async def stream_progress(task_id: str):
      # Server-Sent Events
      pass
  ```

- [ ] **Update frontend** (`app/static/`)
  - [ ] Use new API endpoints
  - [ ] Add progress bar
  - [ ] Show real-time updates

### Python API

- [ ] **Create public API** (`video_gen/__init__.py`)
  ```python
  class Pipeline:
      @staticmethod
      async def create(source, **kwargs):
          orchestrator = PipelineOrchestrator(...)
          return await orchestrator.execute(...)
  ```

- [ ] **Write examples** (`examples/`)
  ```python
  # examples/simple.py
  from video_gen import Pipeline

  result = await Pipeline.create(
      "README.md",
      output_dir="./videos"
  )
  ```

### Resume Capability

- [ ] **Implement checkpoint logic** (`video_gen/pipeline/resume.py`)
  ```python
  class ResumeManager:
      async def can_resume(self, task_id): pass
      async def get_resume_point(self, task_id): pass
  ```

- [ ] **Integrate with orchestrator**
  ```python
  async def execute(self, input_config, resume_from=None):
      if resume_from:
          task = await self.state.restore_task(resume_from)
          stages = self._get_stages_to_run(task)
      # ...
  ```

- [ ] **Test resume**
  ```python
  # Start task
  task = await orchestrator.execute(config)

  # Simulate failure after stage 3
  # ...

  # Resume
  result = await orchestrator.execute(resume_from=task.id)
  assert result.status == "success"
  ```

### Documentation

- [ ] **Update README.md**
  - [ ] New CLI usage
  - [ ] Migration guide
  - [ ] Quick start

- [ ] **Create user guide** (`docs/USER_GUIDE.md`)
  - [ ] All features
  - [ ] Examples
  - [ ] Troubleshooting

- [ ] **API documentation** (`docs/API.md`)
  - [ ] CLI reference
  - [ ] Python API reference
  - [ ] Web API reference

### Deliverables

- [ ] CLI working (`video-gen` command)
- [ ] Web UI refactored
- [ ] Python API intuitive
- [ ] Resume capability tested
- [ ] Documentation complete

---

## 📋 Sprint 5: Cleanup & Deprecation (Week 10)

### Deprecation

- [ ] **Add deprecation warnings** to old scripts
  ```python
  # In each old script:
  warnings.warn(
      "This script is deprecated. Use 'video-gen create' instead.\n"
      "See: docs/MIGRATION_GUIDE.md",
      DeprecationWarning
  )
  ```

- [ ] **Create deprecation table** (`DEPRECATION.md`)
  | Old | New | Deprecated | Removed |
  |-----|-----|------------|---------|
  | `generate_all_videos_unified_v2.py` | `video-gen create` | v2.0 | v3.0 |

### Archive

- [ ] **Move legacy code**
  ```bash
  mkdir -p archive/legacy_scripts
  mv scripts/generate_all_videos_unified_v2.py archive/legacy_scripts/
  mv scripts/generate_video_set.py archive/legacy_scripts/
  # ... etc
  ```

- [ ] **Update .gitignore**
  ```
  archive/
  ```

### Code Cleanup

- [ ] **Remove duplicates**
  ```bash
  # Identify with ruff
  ruff check --select=DUP .

  # Remove confirmed duplicates
  rm scripts/generate_videos_from_set.py
  rm scripts/generate_script_wizard.py
  # ... etc
  ```

- [ ] **Consolidate utilities**
  - [ ] Merge similar functions
  - [ ] Extract shared code
  - [ ] Remove dead code

### Documentation

- [ ] **Update all docs**
  - [ ] README.md (v2.0 features)
  - [ ] GETTING_STARTED.md
  - [ ] All guides reflect new system

- [ ] **Create MIGRATION_GUIDE.md**
  - [ ] v1.x → v2.0 changes
  - [ ] Command mapping
  - [ ] Code examples
  - [ ] FAQ

- [ ] **Update examples**
  - [ ] Use new API
  - [ ] Show best practices
  - [ ] Include common patterns

### Communication

- [ ] **Announce v2.0 release**
  - [ ] Release notes
  - [ ] Blog post
  - [ ] User notification

- [ ] **Support migration**
  - [ ] Answer questions
  - [ ] Update docs based on feedback
  - [ ] Fix migration issues

### Deliverables

- [ ] All old scripts deprecated
- [ ] Legacy code archived
- [ ] Duplicate code removed
- [ ] Documentation updated
- [ ] Migration guide complete

---

## 🎯 Definition of Done (Each Sprint)

### Code Quality

- [ ] All tests pass
- [ ] Coverage ≥ target (80-90%)
- [ ] No linting errors (`ruff check`)
- [ ] Type hints complete (`mypy`)
- [ ] Code reviewed

### Documentation

- [ ] Code comments complete
- [ ] Docstrings for all public APIs
- [ ] Architecture docs updated
- [ ] User guides updated
- [ ] Examples provided

### Testing

- [ ] Unit tests written
- [ ] Integration tests pass
- [ ] E2E tests pass (if applicable)
- [ ] Performance benchmarked
- [ ] Edge cases covered

### Functionality

- [ ] Feature works as designed
- [ ] Error handling implemented
- [ ] Logging added
- [ ] Metrics tracked
- [ ] No regressions

---

## 🚀 Quick Commands Reference

### Development

```bash
# Setup
pip install -e ".[dev]"

# Run tests
pytest --cov=video_gen tests/

# Lint
ruff check .
mypy video_gen/

# Format
black video_gen/
isort video_gen/
```

### Testing

```bash
# Unit tests only
pytest tests/unit/

# Integration tests
pytest tests/integration/

# E2E tests
pytest tests/e2e/

# With coverage
pytest --cov=video_gen --cov-report=html tests/
```

### CLI Testing

```bash
# Install in dev mode
pip install -e .

# Test commands
video-gen create --from README.md --output ./videos
video-gen status <task_id>
video-gen resume <task_id>
video-gen list
```

### Web UI Testing

```bash
# Start server
uvicorn app.main:app --reload

# Test endpoints
curl -X POST http://localhost:8000/api/create \
  -H "Content-Type: application/json" \
  -d '{"input_type":"document","document_path":"README.md"}'
```

---

## 📊 Progress Tracking

### Sprint Status

| Sprint | Status | Progress | Notes |
|--------|--------|----------|-------|
| 1: Foundation | ⏸️ Not Started | 0% | - |
| 2: Input Consolidation | ⏸️ Not Started | 0% | - |
| 3: Generation Unification | ⏸️ Not Started | 0% | - |
| 4: Interface Layer | ⏸️ Not Started | 0% | - |
| 5: Cleanup & Deprecation | ⏸️ Not Started | 0% | - |

**Update this table as you progress!**

Legend:
- ⏸️ Not Started
- 🏃 In Progress
- ✅ Complete
- ⚠️ Blocked

---

## 💡 Implementation Tips

### Start Small

- Implement minimal viable version first
- Add features incrementally
- Test continuously

### Reuse Existing Code

- Wrap old scripts in adapters
- Extract shared logic to modules
- Don't rewrite everything

### Test Early, Test Often

- Write tests before implementation (TDD)
- Run tests after every change
- Keep tests simple and focused

### Document As You Go

- Update docs immediately after changes
- Write examples for new features
- Keep architecture docs in sync

### Communicate

- Share progress regularly
- Ask for help when stuck
- Review code with team

---

**Last Updated:** 2025-10-04
**Status:** Ready for Sprint 1
**Estimated Completion:** 6-10 weeks
