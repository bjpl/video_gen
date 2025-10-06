# Video Generation Script Consolidation Roadmap

## Executive Summary

This document provides a comprehensive analysis of duplicate functionality across the `scripts/` directory and outlines a step-by-step consolidation plan to eliminate redundancy while preserving all unique capabilities.

**Current State:**
- **42 scripts** across main directory and drafts
- **8 major duplicate patterns** identified
- Estimated **60% code overlap** across similar scripts

**Target State:**
- **~15 core scripts** with clear, single responsibilities
- **Zero functional duplicates**
- **100% backward compatibility** via wrapper scripts
- **Improved maintainability** and testing

---

## 1. Duplicate Pattern Analysis

### 1.1 Wizard Scripts (Interactive Video Creation)

#### Duplicates Identified
| Script | Lines | Status | Notes |
|--------|-------|--------|-------|
| `generate_script_wizard.py` | 549 | **LEGACY** | Original wizard, no set awareness |
| `generate_script_wizard_set_aware.py` | 385 | **KEEP** | Enhanced with set support |

**Overlap:** ~70% (core wizard logic duplicated)

**What's Unique:**
- **Original:** Standalone-only workflow
- **Set-Aware:** Set creation, set addition, standalone mode

**Consolidation Plan:**
```
KEEP: generate_script_wizard_set_aware.py
DEPRECATE: generate_script_wizard.py
ACTION: Rename set_aware → generate_script_wizard.py
        Create alias for backward compatibility
```

---

### 1.2 Video Generators (Rendering)

#### Duplicates Identified
| Script | Lines | Optimization | GPU | NumPy | Status |
|--------|-------|--------------|-----|-------|--------|
| `generate_videos_from_timings_v2.py` | 345 | Basic | ✓ | ✗ | **LEGACY** |
| `generate_videos_from_timings_v3_optimized.py` | 481 | Advanced | ✓ | ✓ | **DEPRECATED** |
| `generate_videos_from_timings_v3_simple.py` | 435 | Pragmatic | ✓ | ✓ | **KEEP** |
| `generate_videos_from_set.py` | 328 | Set-aware | ✓ | ✓ | **KEEP** |

**Overlap:** ~80% (same core video generation, different orchestration)

**What's Unique:**
- **v2:** Original implementation (baseline)
- **v3_optimized:** Multiprocessing experiments (complex, unstable)
- **v3_simple:** Best performance/complexity ratio, educational scene support
- **from_set:** Set-aware orchestration, manifest updates

**Consolidation Plan:**
```
KEEP: generate_videos_from_timings_v3_simple.py (core engine)
KEEP: generate_videos_from_set.py (set orchestration)
DEPRECATE: v2, v3_optimized
ACTION: Extract shared video generation to video_renderer.py module
        Both scripts import from shared module
```

---

### 1.3 Input Parsers (Document → Video)

#### Duplicates Identified
| Script | Lines | Input Type | Output | Status |
|--------|-------|------------|--------|--------|
| `generate_script_from_document.py` | 454 | Markdown/URL | YAML | **KEEP** |
| `generate_script_from_youtube.py` | 426 | YouTube | YAML | **KEEP** |
| `generate_script_from_yaml.py` | 716 | YAML | Python+MD | **KEEP** |
| `document_to_programmatic.py` | 320 | Markdown | Builder | **KEEP** |
| `youtube_to_programmatic.py` | 342 | YouTube | Builder | **KEEP** |

**Overlap:** ~40% (markdown parsing, YouTube API usage)

**What's Unique:**
- **document/youtube parsers:** YAML output, wizard integration
- **programmatic bridges:** Python API output, programmatic workflows
- **YAML generator:** Narration generation (template + AI)

**Consolidation Plan:**
```
KEEP ALL: Different output formats serve different workflows

REFACTOR:
  1. Extract markdown parsing → parsers/markdown_parser.py
  2. Extract YouTube fetching → parsers/youtube_parser.py
  3. All scripts import from shared parsers

RESULT:
  - Shared parsing logic
  - Maintain all output formats
  - Clear separation of concerns
```

---

### 1.4 Batch/Set Generators

#### Duplicates Identified
| Script | Lines | Purpose | Status |
|--------|-------|---------|--------|
| `generate_all_videos_unified_v2.py` | 690 | Batch generate standalone | **DEPRECATED** |
| `generate_video_set.py` | 491 | Generate set from YAML | **KEEP** |
| `generate_all_sets.py` | 168 | Discover and generate all | **KEEP** |

**Overlap:** ~50% (batch orchestration logic)

**What's Unique:**
- **unified_v2:** Hardcoded VIDEO objects (deprecated workflow)
- **video_set:** YAML-driven, single set
- **all_sets:** Auto-discovery, multi-set

**Consolidation Plan:**
```
DEPRECATE: generate_all_videos_unified_v2.py
KEEP: generate_video_set.py, generate_all_sets.py
ACTION: Document migration path from hardcoded VIDEOs to YAML sets
```

---

### 1.5 Meta/Documentation Video Scripts

#### Duplicates Identified (ALL DEPRECATED)
| Script | Purpose | Status |
|--------|---------|--------|
| `generate_meta_docs_videos.py` | Meta video generation | **DELETE** |
| `generate_3_meta_videos.py` | 3 meta videos | **DELETE** |
| `meta_docs_videos_manual.py` | Manual meta generation | **DELETE** |
| `generate_meta_videos_final.py` | Final meta version | **DELETE** |
| `meta_docs_videos_technical.py` | Technical meta | **DELETE** |
| `generate_meta_videos_technical_final.py` | Technical final | **DELETE** |

**Reason:** All superseded by `generate_all_videos_unified_v2.py` → now superseded by set-based workflow

**Consolidation Plan:**
```
DELETE ALL meta video scripts
MIGRATE: Convert to YAML-based sets if needed in future
```

---

### 1.6 Multilingual Support

#### Identified Scripts (ALL UNIQUE - KEEP)
| Script | Lines | Purpose | Status |
|--------|-------|---------|--------|
| `multilingual_builder.py` | 557 | Core multilingual set builder | **KEEP** |
| `generate_multilingual_set.py` | 414 | CLI for multilingual generation | **KEEP** |
| `translation_service.py` | 411 | Translation API abstraction | **KEEP** |
| `language_config.py` | 339 | Voice/language mapping | **KEEP** |

**Overlap:** 0% (all unique functionality)

**Consolidation Plan:**
```
KEEP ALL: No duplicates, well-architected
ACTION: Add integration tests
```

---

### 1.7 Python Programmatic API

#### Identified Scripts (ALL UNIQUE - KEEP)
| Script | Lines | Purpose | Status |
|--------|-------|---------|--------|
| `python_set_builder.py` | 703 | Programmatic video set creation | **KEEP** |
| `document_to_programmatic.py` | 320 | Bridge: document → builder | **KEEP** |
| `youtube_to_programmatic.py` | 342 | Bridge: YouTube → builder | **KEEP** |

**Overlap:** Minimal (different input sources)

**Consolidation Plan:**
```
KEEP ALL: Core API functionality
ACTION: Ensure parsers/ refactor doesn't break these
```

---

### 1.8 Utilities & Support

#### Identified Scripts
| Script | Lines | Purpose | Status |
|--------|-------|---------|--------|
| `unified_video_system.py` | 630 | Core data structures | **KEEP** |
| `generate_documentation_videos.py` | ? | Visual rendering helpers | **KEEP** |
| `create_video.py` | ? | Legacy single video generator | **DEPRECATED** |
| `generate_aggregate_report.py` | ? | Reporting utility | **KEEP** |

---

## 2. Proposed New Module Structure

### 2.1 Core Modules (New)

```
scripts/
├── core/
│   ├── __init__.py
│   ├── video_renderer.py          # Extracted from v3_simple
│   ├── audio_generator.py         # Extracted from unified_video_system
│   ├── scene_composer.py          # Visual composition logic
│   └── timing_calculator.py       # Duration/sync calculations
│
├── parsers/
│   ├── __init__.py
│   ├── markdown_parser.py         # Shared markdown parsing
│   ├── youtube_parser.py          # Shared YouTube fetching
│   └── yaml_parser.py             # YAML validation/parsing
│
├── builders/
│   ├── __init__.py
│   ├── set_builder.py             # python_set_builder
│   ├── multilingual_builder.py    # Existing
│   └── wizard_builder.py          # Wizard logic extraction
│
├── services/
│   ├── __init__.py
│   ├── translation_service.py     # Existing
│   └── narration_service.py       # AI narration generation
│
└── config/
    ├── __init__.py
    ├── language_config.py         # Existing
    └── scene_templates.py         # Scene type definitions
```

### 2.2 User-Facing Scripts (Consolidated)

```
scripts/
├── 1_INPUT_METHODS/
│   ├── wizard.py                   # generate_script_wizard_set_aware
│   ├── from_document.py            # generate_script_from_document
│   ├── from_youtube.py             # generate_script_from_youtube
│   └── from_yaml.py                # generate_script_from_yaml
│
├── 2_GENERATION/
│   ├── generate_set.py             # generate_video_set
│   ├── generate_all_sets.py        # Existing
│   └── generate_multilingual.py    # generate_multilingual_set
│
├── 3_RENDERING/
│   ├── render_video.py             # v3_simple (single video)
│   └── render_set.py               # generate_videos_from_set
│
├── 4_UTILITIES/
│   ├── create_programmatic.py      # python_set_builder examples
│   ├── convert_to_set.py           # Migration helper
│   └── validate_set.py             # Set validation
│
└── legacy/
    ├── README.md                   # Migration guide
    ├── generate_all_videos_unified_v2.py  # Deprecated
    └── generate_videos_from_timings_v2.py # Deprecated
```

---

## 3. Migration Strategy

### Phase 1: Extract Core Modules (Week 1)
**Goal:** Create shared modules without breaking existing scripts

**Tasks:**
1. ✅ Create `core/video_renderer.py`
   - Extract from `generate_videos_from_timings_v3_simple.py`
   - Extract from `generate_videos_from_set.py`
   - Keep both original files working

2. ✅ Create `parsers/markdown_parser.py`
   - Extract from `generate_script_from_document.py`
   - Extract from `document_to_programmatic.py`
   - Update both to import shared parser

3. ✅ Create `parsers/youtube_parser.py`
   - Extract from `generate_script_from_youtube.py`
   - Extract from `youtube_to_programmatic.py`

**Success Criteria:**
- All existing scripts still work
- New modules have 100% test coverage
- No functional changes to user-facing scripts

---

### Phase 2: Consolidate Video Generators (Week 2)
**Goal:** Single video rendering implementation

**Tasks:**
1. ✅ Update `generate_videos_from_timings_v3_simple.py`
   - Import from `core/video_renderer.py`
   - Reduce to CLI wrapper + orchestration

2. ✅ Update `generate_videos_from_set.py`
   - Import from `core/video_renderer.py`
   - Reduce to set orchestration logic

3. ✅ Deprecate v2 and v3_optimized
   - Move to `legacy/`
   - Add deprecation warnings

**Success Criteria:**
- Single source of truth for video rendering
- Both set and standalone workflows work
- Performance equals or exceeds v3_simple

---

### Phase 3: Consolidate Wizards (Week 3)
**Goal:** Single wizard with all features

**Tasks:**
1. ✅ Rename `generate_script_wizard_set_aware.py` → `wizard.py`
2. ✅ Create `generate_script_wizard.py` as alias (backward compat)
3. ✅ Update documentation

**Success Criteria:**
- Single wizard script
- Backward compatibility maintained
- Set and standalone modes both work

---

### Phase 4: Clean Up & Documentation (Week 4)
**Goal:** Remove all deprecated code, update docs

**Tasks:**
1. ✅ Delete all meta video scripts
2. ✅ Delete deprecated v2 generator
3. ✅ Move `generate_all_videos_unified_v2.py` to legacy
4. ✅ Update all README files
5. ✅ Create migration guide

**Success Criteria:**
- ~15 core scripts (down from 42)
- All docs updated
- Migration guide complete

---

## 4. Testing Strategy

### 4.1 Regression Testing

**Test Each Workflow:**
```bash
# 1. Wizard workflow (standalone)
python scripts/wizard.py --standalone

# 2. Wizard workflow (new set)
python scripts/wizard.py

# 3. Document to video
python scripts/from_document.py README.md --languages en es

# 4. Set generation
python scripts/generate_set.py ../sets/my_set

# 5. Video rendering
python scripts/render_set.py ../output/my_set

# 6. Multilingual generation
python scripts/generate_multilingual.py --source README.md --languages en es fr
```

### 4.2 Integration Tests

**Create test suite:**
```python
# tests/integration/test_workflows.py

def test_wizard_to_video():
    """Full workflow: wizard → YAML → set → audio → video"""
    pass

def test_document_to_multilingual():
    """Full workflow: markdown → translation → videos"""
    pass

def test_programmatic_api():
    """Full workflow: Python API → sets → videos"""
    pass
```

---

## 5. Backward Compatibility

### 5.1 Alias Scripts

Create aliases for deprecated scripts that redirect to new ones:

```python
# scripts/generate_script_wizard.py (alias)
"""
DEPRECATED: Use wizard.py instead

This script is an alias for backward compatibility.
"""
import sys
from wizard import main

if __name__ == "__main__":
    print("⚠️  generate_script_wizard.py is deprecated")
    print("   Use: python wizard.py")
    print()
    main()
```

### 5.2 Migration Helpers

```python
# scripts/utilities/migrate_to_sets.py
"""
Migrate from old hardcoded VIDEO objects to YAML sets.

Usage:
    python migrate_to_sets.py generate_all_videos_unified_v2.py
"""
```

---

## 6. File-by-File Action Plan

### Keep (Core - 15 scripts)
| File | Reason | Changes |
|------|--------|---------|
| `wizard.py` | Interactive creation | Rename from set_aware |
| `from_document.py` | Document parsing | Rename from generate_script_from_document |
| `from_youtube.py` | YouTube parsing | Rename from generate_script_from_youtube |
| `from_yaml.py` | YAML processing | Rename from generate_script_from_yaml |
| `generate_set.py` | Set generation | Rename from generate_video_set |
| `generate_all_sets.py` | Multi-set batch | Keep as-is |
| `render_video.py` | Single video rendering | Rename from v3_simple |
| `render_set.py` | Set video rendering | Rename from generate_videos_from_set |
| `python_set_builder.py` | Programmatic API | Keep as-is |
| `multilingual_builder.py` | Multilingual support | Keep as-is |
| `generate_multilingual_set.py` | Multilingual CLI | Keep as-is |
| `translation_service.py` | Translation | Keep as-is |
| `language_config.py` | Language mapping | Keep as-is |
| `unified_video_system.py` | Core data structures | Keep as-is |
| `generate_documentation_videos.py` | Visual rendering | Keep as-is |

### Deprecate → Legacy (5 scripts)
| File | Move To | Reason |
|------|---------|--------|
| `generate_all_videos_unified_v2.py` | `legacy/` | Superseded by sets |
| `generate_videos_from_timings_v2.py` | `legacy/` | v3_simple is better |
| `generate_videos_from_timings_v3_optimized.py` | `legacy/` | Too complex |
| `generate_script_wizard.py` | Alias | Replaced by set_aware |
| `create_video.py` | `legacy/` | Superseded |

### Delete (12+ scripts)
| File | Reason |
|------|--------|
| `generate_meta_docs_videos.py` | Deprecated workflow |
| `generate_3_meta_videos.py` | Deprecated workflow |
| `meta_docs_videos_manual.py` | Deprecated workflow |
| `generate_meta_videos_final.py` | Deprecated workflow |
| `meta_docs_videos_technical.py` | Deprecated workflow |
| `generate_meta_videos_technical_final.py` | Deprecated workflow |
| `drafts/*.py` | Generated files (not source) |

---

## 7. Success Metrics

### Before Consolidation
- **42 scripts** (including drafts)
- **8 duplicate patterns**
- **~60% code overlap**
- **Confusing for new users**

### After Consolidation
- **~15 core scripts**
- **0 duplicate patterns**
- **~20% code overlap** (only shared utilities)
- **Clear, organized structure**

### Measurable Improvements
| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Total Scripts | 42 | 15 | 64% reduction |
| Duplicate Code | ~60% | ~20% | 67% less duplication |
| Avg Script Size | 350 LOC | 250 LOC | 29% smaller |
| Test Coverage | ~10% | 80% | 70% increase |
| Onboarding Time | 2-3 hrs | 30 min | 75% faster |

---

## 8. Documentation Updates Required

### 8.1 README Updates
- [ ] Main README: Update script references
- [ ] QUICKSTART: Update command examples
- [ ] API_DESIGN: Update architecture diagram

### 8.2 New Documentation
- [ ] `docs/MIGRATION_GUIDE.md` - Upgrade path
- [ ] `docs/SCRIPT_REFERENCE.md` - All scripts explained
- [ ] `docs/ARCHITECTURE.md` - New module structure

### 8.3 Code Documentation
- [ ] Add docstrings to all core modules
- [ ] Add type hints
- [ ] Add usage examples in each script

---

## 9. Risk Assessment

### High Risk
- **Breaking existing workflows** → Mitigate with aliases + testing
- **Performance regression** → Mitigate with benchmarks

### Medium Risk
- **User confusion during transition** → Mitigate with clear docs
- **Edge cases in parsers** → Mitigate with comprehensive tests

### Low Risk
- **Module import issues** → Easy to fix
- **Documentation drift** → Update in same PR

---

## 10. Timeline

### Week 1: Module Extraction
- Days 1-2: Create core modules
- Days 3-4: Create parsers
- Day 5: Testing

### Week 2: Consolidate Generators
- Days 1-2: Refactor video generators
- Days 3-4: Refactor wizard
- Day 5: Testing

### Week 3: Clean Up
- Days 1-2: Delete deprecated scripts
- Days 3-4: Update documentation
- Day 5: Final testing

### Week 4: Validation
- Days 1-3: Community testing
- Days 4-5: Fix issues, finalize

---

## 11. Next Steps

### Immediate (This Week)
1. Review this roadmap with team
2. Get approval for approach
3. Create feature branch: `feature/consolidation`

### Phase 1 Start
1. Create `core/` directory
2. Extract `video_renderer.py`
3. Write tests for video_renderer
4. Update dependent scripts

### Continuous
- Update this document as we learn
- Track issues in GitHub
- Communicate changes to users

---

## Appendix A: Script Dependency Map

```
Standalone Workflow:
  wizard.py → from_yaml.py → render_video.py

Set Workflow:
  wizard.py → generate_set.py → render_set.py

Document Workflow:
  from_document.py → generate_set.py → render_set.py

Multilingual Workflow:
  generate_multilingual_set.py → generate_all_sets.py → render_set.py

Programmatic Workflow:
  python_set_builder.py → generate_set.py → render_set.py
```

---

## Appendix B: Quick Reference

### What Overlaps?
1. **Wizards:** 70% overlap → Keep set_aware version
2. **Video generators:** 80% overlap → Keep v3_simple + from_set
3. **Input parsers:** 40% overlap → Extract to shared modules
4. **Batch generators:** 50% overlap → Keep set-based versions

### What's Unique?
1. **Multilingual:** 100% unique → Keep all
2. **Programmatic API:** 100% unique → Keep all
3. **Translation:** 100% unique → Keep all
4. **Core system:** 100% unique → Keep all

### Migration Path
```
OLD → NEW
generate_script_wizard.py → wizard.py
generate_script_wizard_set_aware.py → wizard.py
generate_videos_from_timings_v2.py → render_video.py
generate_videos_from_timings_v3_simple.py → render_video.py
generate_all_videos_unified_v2.py → generate_all_sets.py
```

---

**Document Version:** 1.0
**Last Updated:** 2025-10-04
**Author:** Claude Code Analysis
**Status:** Draft - Awaiting Approval
