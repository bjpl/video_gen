# Architecture Documentation - Unified Pipeline System

**Project:** Video Generation System v2.0
**Status:** Design Phase
**Last Updated:** 2025-10-04

---

## 📚 Document Index

This directory contains the complete architecture specifications for the unified pipeline system:

### Core Architecture Documents

1. **[PIPELINE_ARCHITECTURE.md](./PIPELINE_ARCHITECTURE.md)** ⭐ **START HERE**
   - Complete technical design
   - System architecture diagrams
   - Component specifications
   - Class and sequence diagrams
   - Error handling patterns
   - Performance considerations

2. **[STATE_MANAGEMENT_SPEC.md](./STATE_MANAGEMENT_SPEC.md)**
   - Task state model
   - Storage backend design
   - Checkpoint & resume logic
   - Audit trail system
   - Artifact management

3. **[API_CONTRACTS.md](./API_CONTRACTS.md)**
   - Internal API specifications
   - Data Transfer Objects (DTOs)
   - Stage contracts
   - Adapter interfaces
   - Event contracts
   - Error types

4. **[MIGRATION_PLAN.md](./MIGRATION_PLAN.md)**
   - Step-by-step migration strategy
   - 5-phase implementation plan
   - Rollback procedures
   - Testing strategy
   - Success metrics

---

## 🎯 Quick Overview

### The Problem

The current video generation system has:
- **15+ scripts** with overlapping functionality
- **Manual multi-step execution** (5-6 commands required)
- **No unified orchestration** or state management
- **Inconsistent patterns** across CLI, Web, and programmatic interfaces
- **No error recovery** - failures require starting over

### The Solution

A **unified pipeline orchestrator** that:
- ✅ Executes all stages automatically from **one command**
- ✅ Manages **state persistence** and recovery
- ✅ Provides **real-time progress** tracking
- ✅ Ensures **consistency** across all interfaces
- ✅ Supports **resume** from failures

### Expected Benefits

| Metric | Improvement |
|--------|-------------|
| **User commands** | 83% reduction (from 5-6 to 1) |
| **Time to completion** | 50-67% faster |
| **Code maintenance** | 47% fewer scripts |
| **Error recovery** | Automatic vs. manual restart |
| **Learning curve** | 87% easier |

---

## 🏗️ Architecture Overview

### High-Level System Design

```
┌─────────────────────────────────────────────────────────┐
│                    ENTRY LAYER                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────────┐        │
│   │   CLI    │  │  Web UI  │  │  Python API  │        │
│   └────┬─────┘  └────┬─────┘  └────┬─────────┘        │
│        └─────────────┴──────────────┘                   │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              ORCHESTRATION LAYER                        │
│   ┌─────────────────────────────────────────────────┐  │
│   │ PipelineOrchestrator                            │  │
│   │  • Coordinate stage execution                   │  │
│   │  • Manage state transitions                     │  │
│   │  • Handle errors & retries                      │  │
│   │  • Emit progress events                         │  │
│   │  • Support checkpoint/resume                    │  │
│   └─────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  PIPELINE STAGES                        │
│                                                         │
│  1. INPUT ADAPTATION    → Normalize input formats       │
│  2. CONTENT PARSING     → Extract structure             │
│  3. SCRIPT GENERATION   → Create narration             │
│  4. AUDIO GENERATION    → TTS + timing                  │
│  5. VIDEO GENERATION    → Render + encode               │
│  6. OUTPUT HANDLING     → Export + deliver              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Key Components

#### 1. PipelineOrchestrator
- **Purpose:** Coordinate execution of all stages
- **Responsibilities:**
  - Stage execution sequencing
  - State management
  - Error handling & retry
  - Progress tracking
  - Resume from checkpoint

#### 2. StateManager
- **Purpose:** Persist task state across pipeline stages
- **Capabilities:**
  - Task creation & restoration
  - Checkpoint saving
  - Resume from any stage
  - Audit trail
  - Artifact tracking

#### 3. Stage Interface
- **Purpose:** Standard contract for all pipeline stages
- **Methods:**
  - `execute()` - Perform transformation
  - `validate()` - Validate inputs
  - `estimate_duration()` - Predict execution time

#### 4. Input Adapters
- **Purpose:** Normalize different input types to common format
- **Adapters:**
  - DocumentAdapter (MD, TXT, PDF)
  - YouTubeAdapter (video transcripts)
  - WizardAdapter (interactive)
  - YAMLAdapter (config files)
  - ProgrammaticAdapter (Python objects)

#### 5. EventBus
- **Purpose:** Real-time progress updates
- **Events:**
  - ProgressEvent
  - StageStartEvent
  - StageCompleteEvent
  - TaskCreatedEvent
  - ErrorEvent

---

## 📋 Implementation Plan

### 5-Phase Roadmap

#### Phase 1: Foundation (1-2 weeks)
**Goal:** Build core infrastructure

- [ ] Create package structure (`video_gen/`)
- [ ] Implement PipelineOrchestrator
- [ ] Build StateManager
- [ ] Define all data contracts
- [ ] Write foundation tests

**Deliverables:** Core pipeline engine ready

---

#### Phase 2: Input Consolidation (1-2 weeks)
**Goal:** Unify all input methods

- [ ] Create InputAdapter base class
- [ ] Implement all adapters (Document, YouTube, Wizard, YAML)
- [ ] Create adapter registry
- [ ] Run parallel validation tests
- [ ] Add feature flags

**Deliverables:** All inputs normalized to `VideoSetConfig`

---

#### Phase 3: Generation Unification (2-3 weeks)
**Goal:** Merge duplicate generators

- [ ] Unify audio generators (merge 2 scripts)
- [ ] Unify video generators (merge 2 scripts)
- [ ] Consolidate script generation
- [ ] Create shared rendering/TTS modules
- [ ] Run comparison tests

**Deliverables:** Single code path for all video generation

---

#### Phase 4: Interface Layer (1-2 weeks)
**Goal:** User-facing interfaces

- [ ] Build unified CLI (`video-gen` command)
- [ ] Refactor Web UI to use pipeline
- [ ] Create Python API (`from video_gen import Pipeline`)
- [ ] Implement resume capability
- [ ] Update all documentation

**Deliverables:** Complete user experience

---

#### Phase 5: Cleanup & Deprecation (1 week)
**Goal:** Remove old code

- [ ] Add deprecation warnings to old scripts
- [ ] Archive legacy code
- [ ] Remove duplicate code
- [ ] Update all documentation
- [ ] Create migration guide

**Deliverables:** Clean, maintainable codebase

---

## 🔄 Data Flow

### Complete Pipeline Data Flow

```
INPUT (various formats)
  │
  ▼
InputAdapter → VideoSetConfig (normalized)
  │
  ▼
ParsingStage → ParsedContent (structured)
  │
  ▼
ScriptGenerationStage → VideoScript (with narration)
  │
  ▼
AudioGenerationStage → AudioAssets (MP3 + timing)
  │
  ▼
VideoGenerationStage → VideoAssets (MP4 files)
  │
  ▼
OutputStage → PipelineResult (final output)
```

### State Transitions

```
Task Lifecycle:

PENDING → RUNNING → COMPLETED
            ↓
          FAILED → (resume) → RUNNING
            ↓
        CANCELLED
```

---

## 🔌 API Examples

### CLI Usage

```bash
# One command to create video
video-gen create --from README.md --output ./videos

# Resume from failure
video-gen resume task_abc123

# Check status
video-gen status task_abc123

# Advanced options
video-gen create \
  --from document:README.md \
  --languages en,es,fr \
  --voice male \
  --color blue \
  --review
```

### Python API Usage

```python
from video_gen import Pipeline

# Simple usage
result = await Pipeline.create(
    "README.md",
    output_dir="./videos",
    color="blue"
)

print(f"Video: {result.videos[0]}")

# Advanced usage
from video_gen import PipelineOrchestrator, InputConfig

orchestrator = PipelineOrchestrator(...)

result = await orchestrator.execute(
    InputConfig(
        source_type="document",
        source_data={"path": "README.md"},
        accent_color="blue",
        use_ai=True
    )
)
```

### Web API Usage

```javascript
// Create video
const response = await fetch('/api/create', {
  method: 'POST',
  body: JSON.stringify({
    input_type: 'document',
    document_path: 'README.md',
    accent_color: 'blue',
    voice: 'male'
  })
});

const { task_id } = await response.json();

// Stream progress (Server-Sent Events)
const eventSource = new EventSource(`/api/progress/${task_id}`);

eventSource.onmessage = (event) => {
  const progress = JSON.parse(event.data);
  console.log(`${progress.stage}: ${progress.progress * 100}%`);
};
```

---

## 🛠️ Technology Stack

### Core Technologies

- **Python 3.10+** - Core implementation
- **Pydantic** - Data validation & serialization
- **asyncio** - Asynchronous execution
- **FastAPI** - Web API
- **SQLite/JSON** - State persistence
- **FFmpeg** - Video encoding
- **Edge TTS** - Text-to-speech

### Key Libraries

```
# Core
pydantic>=2.0
aiofiles>=23.0
asyncio

# Video Generation
Pillow>=10.0
edge-tts>=6.1.9
yt-dlp>=2023.11.16

# Web UI
fastapi>=0.104.0
uvicorn>=0.24.0

# Testing
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
```

---

## 📊 Design Patterns

### 1. Strategy Pattern
**Used for:** Input adapters

```python
# Different adapters for different input types
adapter = adapter_registry.get_adapter(input_type)
result = await adapter.adapt(raw_input)
```

### 2. Chain of Responsibility
**Used for:** Pipeline stages

```python
# Each stage processes and passes to next
for stage in stages:
    output = await stage.execute(input)
    input = output  # Chain to next stage
```

### 3. Observer Pattern
**Used for:** Event bus

```python
# Stages emit events, subscribers react
event_bus.subscribe(ProgressEvent, on_progress)
event_bus.emit(ProgressEvent(progress=0.5))
```

### 4. Command Pattern
**Used for:** Task execution

```python
# Tasks are commands that can be executed, paused, resumed
task = create_task(input_config)
await task.execute()
await task.pause()
await task.resume()
```

### 5. Repository Pattern
**Used for:** State persistence

```python
# Abstract storage backend
storage = JSONStorageBackend(path)
# OR
storage = SQLiteStorageBackend(path)

state_manager = StateManager(storage)
```

---

## 🧪 Testing Strategy

### Test Pyramid

```
                    ┌─────────────┐
                    │   E2E Tests │  (10%)
                    │  Full flows │
                    └─────────────┘
                  ┌───────────────────┐
                  │ Integration Tests │  (30%)
                  │  Stage combos     │
                  └───────────────────┘
              ┌─────────────────────────────┐
              │      Unit Tests             │  (60%)
              │  Individual components      │
              └─────────────────────────────┘
```

### Test Categories

1. **Unit Tests** (60% of tests)
   - Individual functions/methods
   - Edge cases & error conditions
   - Mock external dependencies

2. **Integration Tests** (30% of tests)
   - Stage interactions
   - State management
   - Adapter → Stage flow

3. **End-to-End Tests** (10% of tests)
   - Complete pipeline execution
   - Real file I/O
   - Performance benchmarks

### Test Coverage Goals

| Component | Target |
|-----------|--------|
| Core Pipeline | 90% |
| Adapters | 85% |
| Stages | 90% |
| State Management | 95% |
| Error Handling | 100% |

---

## 🚨 Error Handling

### Exception Hierarchy

```
PipelineError (base)
├── ValidationError (input validation failed)
├── StageError (stage execution failed)
│   ├── InputStageError
│   ├── AudioGenError
│   └── VideoGenError
├── TaskNotFoundError (resume failed)
├── RetryExhaustedError (all retries failed)
└── ResourceError (disk/memory issues)
```

### Retry Strategy

```python
# Exponential backoff with max attempts
RetryPolicy(
    max_attempts=3,
    base_delay=1.0,      # seconds
    max_delay=60.0,
    exponential_base=2.0
)

# Attempt 1: Immediate
# Attempt 2: Wait 1s
# Attempt 3: Wait 2s
# Attempt 4: Wait 4s (up to max_delay)
```

---

## 📈 Performance Considerations

### Optimization Strategies

1. **Parallel Processing**
   - Batch video generation
   - Max 4 concurrent pipelines
   - Semaphore-based throttling

2. **Caching**
   - Cache TTS results
   - Reuse rendered scenes
   - Cache-key based on content hash

3. **Resource Management**
   - Pool FFmpeg processes
   - Limit memory usage
   - Cleanup temp files proactively

4. **Incremental Processing**
   - Stream large files
   - Process scenes independently
   - Lazy loading where possible

### Performance Targets

| Metric | Target |
|--------|--------|
| Video creation (60s video) | < 5 minutes |
| Memory usage | < 4GB |
| Disk usage (temp) | < 10GB |
| Concurrent tasks | 4-8 |
| Resume overhead | < 5 seconds |

---

## 📝 Documentation Standards

### Code Documentation

```python
class Stage(ABC):
    """
    Abstract base class for all pipeline stages.

    All stages must implement execute() and validate() methods.
    Stages transform input data to output data.

    Example:
        class MyStage(Stage):
            async def execute(self, input):
                # Transform data
                return output
    """

    @abstractmethod
    async def execute(
        self,
        input: StageInput
    ) -> StageOutput:
        """
        Execute this stage.

        Args:
            input: Input data from previous stage

        Returns:
            StageOutput with transformed data

        Raises:
            StageError: If execution fails
        """
        pass
```

### API Documentation

All public APIs documented with:
- Purpose & overview
- Parameters with types
- Return values
- Example usage
- Error conditions

### Architecture Documentation

All architecture docs include:
- Overview & objectives
- Design diagrams (ASCII art)
- Implementation details
- Usage examples
- Migration paths

---

## 🔒 Security Considerations

### Input Validation

- All inputs validated with Pydantic
- Path traversal prevention
- File size limits enforced
- Content type validation

### Resource Limits

```python
PipelineConfig(
    max_memory_mb=4096,      # Memory limit
    max_disk_gb=50,          # Disk usage limit
    stage_timeout_seconds={  # Timeout per stage
        "input": 300,
        "video_generation": 3600
    }
)
```

### Secrets Management

- API keys from environment only
- No secrets in logs
- Sensitive data redacted
- Secure credential storage

---

## 🎓 Learning Resources

### For Implementers

1. **Read in order:**
   - PIPELINE_ARCHITECTURE.md (system design)
   - STATE_MANAGEMENT_SPEC.md (persistence)
   - API_CONTRACTS.md (interfaces)
   - MIGRATION_PLAN.md (implementation)

2. **Key concepts to understand:**
   - Pipeline pattern
   - State machines
   - Event-driven architecture
   - Async/await in Python
   - Dependency injection

3. **External references:**
   - [Pydantic docs](https://docs.pydantic.dev/)
   - [AsyncIO tutorial](https://docs.python.org/3/library/asyncio.html)
   - [FFmpeg guide](https://ffmpeg.org/documentation.html)

### For Users

1. **Getting started:**
   - See main README.md
   - Follow quickstart guide
   - Review examples/

2. **Migration from v1.x:**
   - Read MIGRATION_GUIDE.md
   - Check script mapping table
   - Review CLI changes

---

## 📬 Support & Communication

### Getting Help

- **Documentation:** Read architecture docs first
- **Issues:** GitHub Issues for bugs/features
- **Discussions:** GitHub Discussions for questions
- **Chat:** Slack #video-gen-dev

### Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for:
- Code style guide
- PR process
- Review checklist
- Testing requirements

### Release Process

1. Create feature branch
2. Implement with tests
3. Update documentation
4. Submit PR
5. Code review
6. Merge to main
7. Deploy to staging
8. Validate
9. Deploy to production
10. Update changelog

---

## 📅 Roadmap

### v2.0 (Current - Q4 2025)
- ✅ Unified pipeline architecture
- ✅ State management & resume
- ✅ Consolidated generators
- ✅ Unified CLI/Web/API

### v2.1 (Q1 2026)
- [ ] Cloud storage integration
- [ ] Distributed processing
- [ ] Advanced caching
- [ ] Performance dashboard

### v2.2 (Q2 2026)
- [ ] ML-powered narration
- [ ] Auto scene detection
- [ ] Voice cloning support
- [ ] Real-time preview

### v3.0 (Q3 2026)
- [ ] Plugin system
- [ ] Custom renderers
- [ ] Template marketplace
- [ ] Collaborative editing

---

## 📄 License

This architecture and implementation are part of the Video Generation System project.

---

## ✨ Architecture Principles Summary

1. **Single Responsibility** - Each component has one clear purpose
2. **Dependency Injection** - All dependencies are injected
3. **Interface Segregation** - Minimal interfaces
4. **Event-Driven** - Progress via events
5. **Fail-Fast** - Validate early, fail gracefully
6. **Stateful** - Persist everything for resume
7. **Testable** - All components mockable
8. **Documented** - Self-documenting code

---

**Last Updated:** 2025-10-04
**Status:** Design Phase Complete
**Next Step:** Begin Phase 1 Implementation
**Document Owner:** Architecture Team
