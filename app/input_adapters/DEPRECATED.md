# DEPRECATED: app/input_adapters

**Status:** This module is deprecated as of 2025-10-06

**Use instead:** `video_gen.input_adapters`

---

## Why Deprecated?

The `app/input_adapters/` system was created for the FastAPI web interface but has been superseded by the unified pipeline architecture.

**Current architecture:**
- `app/main.py` uses `video_gen.pipeline` (unified orchestration)
- Pipeline uses `video_gen.input_adapters` internally
- `app/input_adapters` is redundant

---

## Migration Guide

### Before (Deprecated):
```python
from app.input_adapters.document import DocumentAdapter
from app.input_adapters.base import VideoSet

adapter = DocumentAdapter()
video_set = adapter.parse(source="README.md")  # Sync
```

### After (Current):
```python
from video_gen.input_adapters.document import DocumentAdapter
from video_gen.shared.models import VideoSet

adapter = DocumentAdapter()
result = await adapter.adapt(source="README.md")  # Async
video_set = result.video_set if result.success else None
```

### Or Use Pipeline (Recommended):
```python
from video_gen.pipeline import get_pipeline
from video_gen.shared.models import InputConfig

pipeline = get_pipeline()
input_config = InputConfig(
    input_type="document",
    source="README.md",
    accent_color=(59, 130, 246),
    voice="male"
)
result = await pipeline.execute(input_config)
```

---

## API Differences

| Feature | app/ (Deprecated) | video_gen/ (Current) |
|---------|-------------------|---------------------|
| **Execution** | Synchronous | Asynchronous |
| **Method** | `.parse()` | `.adapt()` |
| **Return** | VideoSet | InputAdapterResult |
| **Error handling** | Exceptions | Result.success/error |
| **VideoSet source** | app.input_adapters.base | video_gen.shared.models |
| **Pipeline integration** | No | Yes |

---

## Deprecation Timeline

- **2025-10-06**: Marked as deprecated
- **Next version**: Add runtime warnings
- **Future version**: Remove entirely

---

## Files in This Directory

All files in `app/input_adapters/` are deprecated:

- `base.py` - Use `video_gen.input_adapters.base`
- `document.py` - Use `video_gen.input_adapters.document`
- `yaml_file.py` - Use `video_gen.input_adapters.yaml_file`
- `youtube.py` - Use `video_gen.input_adapters.youtube`
- `programmatic.py` - Use `video_gen.input_adapters.programmatic`
- `wizard.py` - Use `video_gen.input_adapters.wizard`
- `examples.py` - Use `video_gen.input_adapters.examples`

---

## Need Help?

See:
- `video_gen/input_adapters/README.md` - Current adapter documentation
- `docs/architecture/ARCHITECTURE_ANALYSIS.md` - System architecture
- `docs/SESSION_SUMMARY_2025-10-06.md` - Recent changes

---

**Use `video_gen.input_adapters` for all new code.**
