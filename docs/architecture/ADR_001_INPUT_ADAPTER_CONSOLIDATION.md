# ADR 001: Input Adapter Consolidation and API Standardization

**Status:** Proposed
**Date:** 2025-10-11
**Decision Makers:** Development Team
**Technical Story:** Plan B - Technical Debt Elimination Sprint

## Context and Problem Statement

The video_gen project currently has **two complete implementations** of the input adapter system:

1. **Deprecated System** (`app/input_adapters/`):
   - Synchronous API: `parse(source: str, **options) -> VideoSet`
   - Returns `VideoSet` directly
   - Used by 116+ test files
   - Simpler error handling (exceptions only)

2. **Canonical System** (`video_gen/input_adapters/`):
   - Asynchronous API: `async adapt(source: Any, **kwargs) -> InputAdapterResult`
   - Returns `InputAdapterResult` wrapper with success/error/metadata
   - Modern async/await pattern
   - Better structured error reporting

This **duplication causes:**
- ~3,600 lines of duplicated code
- 30% velocity reduction (maintaining both systems)
- API confusion for developers
- Increased testing burden
- Migration complexity for tests

## Decision Drivers

1. **Code Quality:** Eliminate ~3,600 lines of duplicate code
2. **Velocity:** Remove 30% overhead from dual maintenance
3. **Consistency:** Single, clear API for all input adapters
4. **Modern Patterns:** async/await is standard for I/O operations
5. **Error Handling:** InputAdapterResult provides better structure
6. **Future Maintenance:** Easier to enhance single system

## Considered Options

### Option 1: Keep Both Systems (Status Quo)
**Pros:**
- No migration work required
- Existing tests unchanged
- No breaking changes

**Cons:**
- Continued 30% velocity tax
- Growing technical debt
- Developer confusion
- Harder to add new features

### Option 2: Migrate to Canonical System with Compatibility Layer
**Pros:**
- Clean migration path
- Tests can be migrated incrementally
- Maintains backward compatibility during transition
- Eventually reaches single clean system

**Cons:**
- Requires compatibility layer implementation
- 116 test files need migration
- ~2 weeks of effort

### Option 3: Revert Canonical System to Match Deprecated
**Pros:**
- Minimal test changes
- Simpler synchronous API

**Cons:**
- Loses async benefits for I/O
- Worse error handling structure
- Moves backwards from better design
- Still requires code consolidation

## Decision Outcome

**Chosen option: Option 2 - Migrate to Canonical System with Compatibility Layer**

### Rationale:
1. **Best Long-Term Solution:** Ends with single, modern, well-designed system
2. **Safe Migration:** Compatibility layer prevents breaking existing code
3. **Incremental:** Can migrate tests in batches (20 at a time)
4. **Future-Proof:** Async/await is the right pattern for I/O operations
5. **Better Design:** InputAdapterResult wrapper improves error handling

### Positive Consequences:
- ✅ Single source of truth for input adapters
- ✅ 30-40% velocity improvement post-migration
- ✅ Cleaner, more maintainable codebase
- ✅ Modern async patterns throughout
- ✅ Better error handling and reporting
- ✅ Easier to add new adapter types

### Negative Consequences:
- ⚠️ 12-15 days migration effort required
- ⚠️ Compatibility layer adds temporary complexity
- ⚠️ Risk of breaking tests during migration
- ⚠️ Requires careful coordination and testing

## Implementation Strategy

### Phase 1: Compatibility Layer (Days 1-2)
```python
# video_gen/input_adapters/compat.py
"""
Compatibility layer for migrating from deprecated app.input_adapters
to canonical video_gen.input_adapters.

This module provides:
1. Sync wrappers for async adapters (parse -> adapt)
2. VideoSet extraction from InputAdapterResult
3. Drop-in replacements for all deprecated adapters
"""

import asyncio
from typing import Any

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet


class CompatAdapter:
    """Synchronous wrapper for async InputAdapter.

    Provides deprecated .parse() method that internally calls
    the canonical async .adapt() method.
    """

    def __init__(self, async_adapter: InputAdapter):
        self._adapter = async_adapter

    def parse(self, source: str, **options) -> VideoSet:
        """Synchronous parse method (deprecated pattern).

        Internally runs async adapt() and extracts VideoSet.
        Raises exception on failure for backward compatibility.
        """
        # Run async adapt in sync context
        result = asyncio.run(self._adapter.adapt(source, **options))

        # Extract VideoSet or raise exception (legacy behavior)
        if not result.success:
            raise ValueError(f"Adapter failed: {result.error}")

        return result.video_set


# Drop-in replacements
class DocumentAdapter(CompatAdapter):
    """Backward-compatible DocumentAdapter."""
    def __init__(self):
        from .document import DocumentAdapter as AsyncDoc
        super().__init__(AsyncDoc())


class YouTubeAdapter(CompatAdapter):
    """Backward-compatible YouTubeAdapter."""
    def __init__(self):
        from .youtube import YouTubeAdapter as AsyncYT
        super().__init__(AsyncYT())


# Export all for easy migration
__all__ = [
    "CompatAdapter",
    "DocumentAdapter",
    "YouTubeAdapter",
    # ... other adapters
]
```

### Phase 2: Test Migration (Days 3-10)
```python
# scripts/migrate_adapter_tests.py
"""
Automated test migration script.

Transforms:
  from app.input_adapters import DocumentAdapter
  →
  from video_gen.input_adapters.compat import DocumentAdapter

Or optionally (full migration):
  from app.input_adapters import DocumentAdapter
  →
  from video_gen.input_adapters import DocumentAdapter
  # Update to use async/await and InputAdapterResult
"""
```

**Migration Batches:**
- Batch 1 (Day 3): 20 tests - test compatibility layer
- Batch 2 (Day 4): 20 tests - verify pattern
- Batches 3-5 (Days 5-8): Remaining 76 tests
- Day 9: Full test suite verification
- Day 10: Remove compatibility layer, final async migration

### Phase 3: Cleanup (Days 11-12)
1. Remove `app/input_adapters/` directory
2. Remove compatibility layer
3. Update all remaining code to async patterns
4. Final test suite run
5. Documentation updates

## Compliance and Validation

### Success Metrics:
- [ ] Zero code duplication in adapter system
- [ ] All 116+ tests passing after migration
- [ ] 30-40% velocity improvement measured
- [ ] No deprecated imports remaining
- [ ] Documentation reflects single adapter system

### Testing Strategy:
1. **Compatibility Layer Tests:** Verify sync wrapper works correctly
2. **Incremental Migration:** Test after each 20-test batch
3. **Integration Tests:** Full pipeline tests after migration
4. **Performance Tests:** Ensure async doesn't slow down
5. **Regression Tests:** All 509+ tests must pass

### Rollback Plan:
If critical issues discovered:
1. Keep compatibility layer permanently
2. Revert individual test migrations
3. Document decision to maintain both systems
4. Update ADR to "Rejected" or "Superseded"

## Links and References

- [ISSUES.md](../../ISSUES.md) - Issue #3: Deprecated app/input_adapters Module
- [SKIPPED_TESTS_ANALYSIS.md](../testing/SKIPPED_TESTS_ANALYSIS.md)
- [INPUT_ADAPTERS_QUICK_REF.md](../reference/INPUT_ADAPTERS_QUICK_REF.md)
- [2025-10-10_startup_report.md](../../daily_dev_startup_reports/2025-10-10_startup_report.md) - Plan B Details

## Follow-Up Actions

- [ ] Implement compatibility layer
- [ ] Write compatibility layer tests
- [ ] Create migration script
- [ ] Migrate tests in batches
- [ ] Remove deprecated directory
- [ ] Update all documentation
- [ ] Measure velocity improvement

---

**Template Version:** ADR 1.0
**Next Review Date:** 2025-10-25 (2 weeks post-implementation)
