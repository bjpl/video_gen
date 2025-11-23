# Architecture Decisions Overview

**Complete index of all Architecture Decision Records (ADRs)**

Last Updated: 2025-10-16

---

## Purpose of ADRs

Architecture Decision Records document **why** we made key technical decisions, not just **what** we built. They help:

- **Onboard new developers** - Understand rationale behind design choices
- **Prevent rework** - Avoid revisiting settled decisions
- **Learn from experience** - Document what worked and what didn't
- **Maintain consistency** - Establish patterns for similar problems
- **Track evolution** - See how architecture evolved over time

---

## Quick Reference

| ADR | Title | Status | Date | Impact |
|-----|-------|--------|------|--------|
| [ADR-001](./ADR_001_INPUT_ADAPTER_CONSOLIDATION.md) | Input Adapter Consolidation | Proposed → In Progress | 2025-10-11 | 🔴 High - Eliminates 3600 lines of duplicate code |
| [ADR-002](./ADR_002_MODULAR_RENDERER_SYSTEM.md) | Modular Renderer System | Accepted | 2025-10-16 | 🟢 High - 100% test coverage, 7 modules |
| [ADR-003](./ADR_003_AI_INTEGRATION_STRATEGY.md) | AI Integration Strategy | Accepted | 2025-10-16 | 🟡 Medium - $0.05-0.15 per video, +34% engagement |
| [ADR-004](./ADR_004_TESTING_STRATEGY.md) | Testing Strategy | Accepted | 2025-10-16 | 🟢 High - 79% coverage, 475 passing tests |
| [ADR-005](./ADR_005_CONFIGURATION_SYSTEM.md) | Configuration System | Accepted | 2025-10-16 | 🟢 Medium - Single source of truth, secure |

**Legend:**
- 🔴 High Impact - Major architectural change
- 🟡 Medium Impact - Significant but contained change
- 🟢 Low-Medium Impact - Important but localized

---

## Decision Timeline

```
2025-10-11: ADR-001 - Input Adapter Consolidation (Proposed)
            ├─ Phase 1: Compatibility layer implemented ✅
            ├─ Phase 2: Test migration (in progress)
            └─ Phase 3: Cleanup (planned)

2025-10-16: ADR-002 - Modular Renderer System (Accepted)
            ├─ 7 renderer modules
            ├─ 100% test coverage achieved
            └─ 12+ scene types supported

2025-10-16: ADR-003 - AI Integration Strategy (Accepted)
            ├─ Claude Sonnet 4.5 integration
            ├─ Scene-position awareness
            └─ Usage tracking implemented

2025-10-16: ADR-004 - Testing Strategy (Accepted)
            ├─ Multi-tier testing (unit/integration/slow)
            ├─ pytest markers and async support
            └─ 79% coverage achieved

2025-10-16: ADR-005 - Configuration System (Accepted)
            ├─ Singleton config class
            ├─ Environment variable support
            └─ Cross-platform compatibility
```

---

## ADR Details

### ADR-001: Input Adapter Consolidation

**Problem:** Duplicate input adapter systems (app/ vs. video_gen/)
**Decision:** Migrate to canonical async system with compatibility layer
**Status:** In Progress (Phase 1 complete, Phase 2 underway)

**Key Points:**
- Eliminates 3,600 lines of duplicate code
- Compatibility layer provides migration path
- 30-40% velocity improvement expected
- 12-15 day migration effort

**Links:**
- [Full ADR](./ADR_001_INPUT_ADAPTER_CONSOLIDATION.md)
- [Compatibility Layer Tests](../../tests/test_compat_layer.py) - 47 tests, 100% passing
- [ISSUES.md](../../ISSUES.md) - Issue #3

---

### ADR-002: Modular Renderer System Design

**Problem:** How to organize 12+ scene renderers with shared utilities
**Decision:** Modular function-based renderers with base utilities
**Status:** Accepted (Implemented and tested)

**Key Points:**
- 7 renderer modules (basic, educational, checkpoint, comparison, etc.)
- 100% test coverage (142 tests)
- Function-based approach (no OOP overhead)
- Consistent styling via constants module
- Average 50-80ms frame generation time

**Architecture:**
```
video_gen/renderers/
├── base.py              # Shared utilities
├── constants.py         # Styling constants
├── basic_scenes.py      # Title, command, list, outro
├── educational_scenes.py # Quiz, objectives, exercises
├── checkpoint_scenes.py # Progress checkpoints
└── comparison_scenes.py # Code/concept comparisons
```

**Links:**
- [Full ADR](./ADR_002_MODULAR_RENDERER_SYSTEM.md)
- [Renderer API](../api/RENDERER_API.md)
- [Renderer Tests](../../tests/test_renderers.py)

---

### ADR-003: AI Integration Strategy

**Problem:** Template-based narration sounds robotic and repetitive
**Decision:** Claude Sonnet 4.5 with scene-position awareness
**Status:** Accepted (Implemented with Plan B enhancements)

**Key Points:**
- Claude Sonnet 4.5 chosen over GPT-4 (better technical accuracy)
- Scene-position aware prompts (opening/middle/closing)
- Cost tracking and validation ($0.05-0.15 per video)
- Graceful fallback to original narration
- +34% engagement improvement (human evaluation)

**Enhancement Flow:**
```
Template Narration → AI Enhancement → Validation → Voice Synthesis
                     (Claude API)    (Quality Checks)
```

**Links:**
- [Full ADR](./ADR_003_AI_INTEGRATION_STRATEGY.md)
- [AI Narration Quickstart](../AI_NARRATION_QUICKSTART.md)
- [Implementation](../../video_gen/script_generator/ai_enhancer.py)

---

### ADR-004: Testing Strategy and Organization

**Problem:** Mix of sync/async code, slow tests blocking development
**Decision:** Multi-tier testing with pytest markers
**Status:** Accepted (79% coverage achieved)

**Key Points:**
- Three test tiers: unit, integration, slow (E2E)
- pytest markers for filtering (`-m "not slow"`)
- pytest-asyncio for async testing
- 30s fast test runs, 5min full suite
- 475 passing tests, 128 intentionally skipped

**Test Organization:**
- **Unit tests** (< 0.1s) - Fast, isolated, mocked I/O
- **Integration tests** (< 2s) - Component interactions
- **Slow tests** (> 5s) - End-to-end workflows

**Coverage by Module:**
- Renderers: 100% (142 tests)
- Input Adapters: 85% (132 tests)
- Pipeline: 78% (86 tests)
- Overall: 79%

**Links:**
- [Full ADR](./ADR_004_TESTING_STRATEGY.md)
- [Testing Guide](../testing/TESTING_GUIDE.md)
- [pytest.ini](../../pytest.ini)

---

### ADR-005: Configuration System Design

**Problem:** Configuration scattered across files, hardcoded values
**Decision:** Singleton config class with environment variables
**Status:** Accepted (Implemented)

**Key Points:**
- Single source of truth (video_gen/shared/config.py)
- Environment variable support (.env file)
- API keys from environment only (security)
- Cross-platform path detection (FFmpeg auto-discovery)
- Follows 12-factor app principles

**Configuration Categories:**
- Paths: Base directories, output locations
- Video: Dimensions (1920x1080), FPS (30)
- External Tools: FFmpeg path (auto-detected)
- API Keys: Anthropic, OpenAI, YouTube
- Presets: Voice configs, color palettes
- Performance: Worker counts, memory limits

**Usage:**
```python
from video_gen.shared.config import config

output_path = config.output_dir / "video.mp4"
api_key = config.get_api_key("anthropic")
voice = config.get_voice("male")
color = config.get_color("blue")
```

**Links:**
- [Full ADR](./ADR_005_CONFIGURATION_SYSTEM.md)
- [Implementation](../../video_gen/shared/config.py)
- [.env.example](../../.env.example)

---

## Cross-Cutting Concerns

### How ADRs Relate to Each Other

**Configuration → All Systems**
- ADR-005 provides config foundation
- Used by renderers (ADR-002) for styling
- Used by AI integration (ADR-003) for API keys
- Used by tests (ADR-004) for mocking

**Testing → All Development**
- ADR-004 establishes test patterns
- Applied to renderers (ADR-002): 100% coverage
- Applied to adapters (ADR-001): migration validation
- Applied to AI (ADR-003): API mocking

**Modularity Pattern (Repeated)**
- ADR-001: Modular adapters
- ADR-002: Modular renderers
- Both follow similar principles:
  - Function-based approach
  - Clear separation of concerns
  - Standardized interfaces
  - High test coverage

**Async/Await Pattern (Consistent)**
- ADR-001: Async adapters
- ADR-003: Async AI enhancement
- ADR-004: Async testing patterns
- Consistent async-first design

---

## Decision-Making Process

### How We Make Architecture Decisions

1. **Identify Problem**: Document pain points and requirements
2. **Research Alternatives**: Evaluate 3-5 options with pros/cons
3. **Prototype (if needed)**: Build small proofs-of-concept
4. **Document Decision**: Create ADR with full rationale
5. **Implement**: Build according to ADR
6. **Validate**: Measure against success criteria
7. **Review**: Periodic review (quarterly or as needed)

### When to Create an ADR

✅ **Create ADR for:**
- Major architectural decisions (frameworks, databases)
- Design patterns affecting multiple modules
- Significant trade-offs (performance vs. simplicity)
- Technology selection (AI model, testing framework)
- Breaking changes to public APIs

❌ **Don't create ADR for:**
- Minor implementation details
- Obvious choices (use Python for Python project)
- Reversible decisions easily changed
- Internal refactoring (unless teaching moment)

### ADR Lifecycle

**Proposed** → Under consideration, seeking feedback
**Accepted** → Approved and implemented
**Deprecated** → Superseded by newer decision
**Rejected** → Considered but not adopted
**Superseded** → Replaced by specific other ADR

---

## Lessons Learned

### What Worked Well

✅ **Function-based over OOP (ADR-002)**
- Simpler to understand and test
- No overhead from instantiation
- Natural for stateless operations
- Easy to compose

✅ **Async-first design (ADR-001, ADR-003)**
- Matches I/O-bound operations
- Better for scalability
- Modern Python idiom
- Testable with pytest-asyncio

✅ **Environment variables for config (ADR-005)**
- Secure (no secrets in code)
- Flexible (easy to override)
- Cloud-native friendly
- Standard practice

✅ **Multi-tier testing (ADR-004)**
- Fast feedback in development
- Comprehensive coverage in CI
- Clear test organization
- Flexible filtering

### What We'd Do Differently

⚠️ **Earlier API consolidation (ADR-001)**
- Duplication accumulated technical debt
- Should have unified sooner
- Lesson: Consolidate early, before duplication grows

⚠️ **More upfront planning for async (ADR-001)**
- Sync→async migration is complex
- Should have started async from beginning
- Lesson: Design for async from day one

⚠️ **Pydantic for config validation (ADR-005)**
- Manual validation is tedious
- Pydantic would provide better type safety
- Lesson: Consider stronger validation libraries

---

## Future ADRs (Planned)

Potential decisions to document:

**ADR-006: Pipeline Architecture** (Q1 2026)
- Document 6-stage pipeline design
- Stage responsibilities and interfaces
- State management between stages

**ADR-007: API Design Principles** (Q1 2026)
- REST API vs. GraphQL
- Versioning strategy
- Authentication approach

**ADR-008: Deployment Strategy** (Q2 2026)
- Containerization (Docker)
- Cloud platform selection
- CI/CD pipeline design

**ADR-009: Observability and Monitoring** (Q2 2026)
- Logging strategy (already using structured logging)
- Metrics collection
- Error tracking

**ADR-010: Multilingual Support** (Q3 2026)
- Translation approach
- Voice synthesis for multiple languages
- UI localization

---

## Reading Order for New Developers

**1. Start here** (15 min):
- This document (overview)
- [ARCHITECTURE_ANALYSIS.md](./ARCHITECTURE_ANALYSIS.md) - System architecture

**2. Core decisions** (45 min):
- ADR-005: Configuration System (how system is configured)
- ADR-002: Modular Renderer System (how videos are rendered)
- ADR-004: Testing Strategy (how to write tests)

**3. Advanced topics** (30 min):
- ADR-003: AI Integration Strategy (optional AI features)
- ADR-001: Input Adapter Consolidation (migration in progress)

**Total reading time:** ~90 minutes for complete understanding

---

## Contributing

### How to Propose a New ADR

1. **Copy Template**:
   ```bash
   cp docs/architecture/ADR_TEMPLATE.md docs/architecture/ADR_XXX_TITLE.md
   ```

2. **Fill in Sections**:
   - Context: What problem are you solving?
   - Decision: What did you choose?
   - Alternatives: What else did you consider? (3-5 options)
   - Consequences: What are the trade-offs?

3. **Submit for Review**:
   - Create PR with ADR
   - Tag relevant stakeholders
   - Discuss in team meeting if major decision

4. **Update This Index**:
   - Add entry to Quick Reference table
   - Add to Decision Timeline
   - Add to ADR Details section

### ADR Template

See [ADR_TEMPLATE.md](./ADR_TEMPLATE.md) for full template (if created).

Basic structure:
```markdown
# ADR-XXX: Title

**Status:** Proposed | Accepted | Deprecated | Rejected | Superseded
**Date:** YYYY-MM-DD
**Deciders:** Development Team

## Context and Problem Statement
[Describe the problem]

## Decision
[What you chose]

## Alternatives Considered
[What else you evaluated]

## Decision Outcome
[Rationale and consequences]

## Links and References
[Related docs and code]
```

---

## Maintenance

**Review Schedule:**
- Quarterly review of all ADRs (check if still relevant)
- Update ADRs when architecture changes
- Deprecate ADRs when superseded

**Next Review:** 2026-01-16 (3 months)

---

## Resources

### Internal Documentation
- [ARCHITECTURE_ANALYSIS.md](./ARCHITECTURE_ANALYSIS.md) - Complete system architecture
- [API_CONTRACTS.md](./API_CONTRACTS.md) - API interface contracts
- [COMPONENT_DIAGRAM.md](./COMPONENT_DIAGRAM.md) - Component relationships
- [PIPELINE_ARCHITECTURE.md](./PIPELINE_ARCHITECTURE.md) - Pipeline design

### External References
- [ADR GitHub Organization](https://adr.github.io/) - ADR best practices
- [Michael Nygard's ADRs](http://thinkrelevance.com/blog/2011/11/15/documenting-architecture-decisions) - Original ADR proposal
- [12-Factor App](https://12factor.net/) - Configuration and deployment principles

---

## Summary

We have documented **5 major architecture decisions** covering:

1. **Input system** - Consolidation to async adapter pattern
2. **Renderer system** - Modular function-based renderers
3. **AI integration** - Claude Sonnet 4.5 with scene awareness
4. **Testing** - Multi-tier strategy with pytest
5. **Configuration** - Singleton with environment variables

These decisions establish patterns for:
- ✅ Modularity and separation of concerns
- ✅ Async-first design for I/O operations
- ✅ Function-based over OOP where appropriate
- ✅ Test-driven development with high coverage
- ✅ Secure configuration management
- ✅ Cross-platform compatibility

**Total documentation:** 1,500+ lines across 5 ADRs
**Total reading time:** ~2 hours for complete understanding

---

*This overview is maintained as ADRs are added or updated. Last updated: 2025-10-16*
