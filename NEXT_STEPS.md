# Next Steps - UI/API Alignment & Test Migration

**Date:** October 11, 2025
**Status:** 90% Complete - 3-4 days of work remaining

---

## 🚨 CRITICAL (Do First)

### 1. Fix Path Traversal Security Vulnerability
**Priority:** CRITICAL ⚠️
**Effort:** 2 hours
**File:** `video_gen/input_adapters/document.py`

**Issue:**
DocumentAdapter accepts absolute paths to system files without validation.

**Test Failing:**
```bash
python3 -m pytest tests/test_security.py::TestPathTraversalProtection::test_blocks_absolute_path_to_system_files -xvs
```

**Required Fix:**
```python
# Add to DocumentAdapter.adapt() method:
def _validate_path(self, path: str) -> bool:
    """Validate file path for security"""
    path_obj = Path(path).resolve()
    
    # Block absolute paths to system directories
    system_dirs = ['/etc', '/sys', '/proc', '/root', '/boot', '/var']
    if any(str(path_obj).startswith(d) for d in system_dirs):
        return False
    
    # Only allow relative paths or paths within project
    cwd = Path.cwd()
    try:
        path_obj.relative_to(cwd)
        return True
    except ValueError:
        return False
```

---

## 🟡 HIGH PRIORITY (Do This Week)

### 2. Migrate Dynamic Imports (58 remaining)
**Priority:** HIGH
**Effort:** 4 hours
**Automated:** Yes

**Files needing migration:**
- `tests/test_real_integration.py` (21 imports)
- `tests/test_quick_win_validation.py` (19 imports)
- `tests/test_pipeline_integration.py` (8 imports)
- `tests/test_adapters_coverage.py` (8 imports)
- `tests/test_input_adapters.py` (2 imports)

**Automated Script:**
```bash
# Run automated migration (20 tests at a time)
python scripts/migrate_adapter_tests.py --batch-size 20

# Verify after each batch
python3 -m pytest tests/ -k "not slow" -q
```

**Manual Pattern:**
```python
# Replace this:
from app.input_adapters import DocumentAdapter

# With this:
from video_gen.input_adapters.compat import DocumentAdapter
```

### 3. Fix API Compatibility Tests (49 failures)
**Priority:** HIGH
**Effort:** 8 hours

**Common issues:**

#### Issue 1: YAMLAdapter constructor
```python
# Old (deprecated):
adapter = YAMLAdapter(generate_narration=True)

# New:
adapter = YAMLAdapter()
# Pass generate_narration in adapt() call instead
```

#### Issue 2: Removed methods
```python
# Old (deprecated):
video_set.export_to_yaml(path)
config = video_set.config

# New:
# Use YAML library directly or skip test
yaml.dump(video_set.dict(), path)
# Access video_set attributes directly
```

#### Issue 3: Scene factory functions
```python
# Old (deprecated):
scene = adapter.create_scene('title', {'title': 'Test'}, 'narration')

# New:
from video_gen.shared.models import SceneConfig
scene = SceneConfig(
    scene_type='title',
    visual_content={'title': 'Test'},
    narration='narration'
)
```

**Run tests to verify:**
```bash
python3 -m pytest tests/test_real_integration.py -v
```

---

## 🟢 MEDIUM PRIORITY (Next Sprint)

### 4. Complete Phase 3 UI/API Alignment (10% remaining)
**Priority:** MEDIUM
**Effort:** 10 hours

#### Feature 1: VideoSet Batch Processing
```bash
# Add to create_video.py:
parser.add_argument('--video-set', metavar='FILE',
                   help='YAML file defining multiple related videos')
```

**Example VideoSet YAML:**
```yaml
set_id: "python_course"
name: "Complete Python Course"
videos:
  - video_id: "lesson_01"
    title: "Python Basics"
    scenes: [...]
  - video_id: "lesson_02"
    title: "Functions"
    scenes: [...]
```

#### Feature 2: Resume from Stage
```bash
# Add to create_video.py:
parser.add_argument('--resume-from',
                   choices=['parse', 'script', 'audio', 'video', 'merge'],
                   help='Resume from specific pipeline stage')
```

### 5. Update Documentation
**Priority:** MEDIUM
**Effort:** 2 hours

**Files to update:**
- [ ] `README.md` - Add new CLI flags
- [ ] `docs/USER_GUIDE.md` - Examples of new features
- [ ] `docs/api/API_PARAMETERS_REFERENCE.md` - Complete API reference
- [ ] `docs/TEST_MIGRATION_STATUS.md` - Mark as complete
- [ ] Security advisory for path traversal fix

---

## ⏰ Timeline

### Day 1 (Today)
- [x] Complete validation report
- [ ] Fix path traversal security issue (2h)
- [ ] Run security tests to verify

### Day 2
- [ ] Migrate dynamic imports batch 1-3 (4h)
- [ ] Fix API compatibility tests batch 1 (4h)

### Day 3
- [ ] Fix API compatibility tests batch 2 (4h)
- [ ] Begin Phase 3 features (4h)

### Day 4
- [ ] Complete Phase 3 features (6h)
- [ ] Update documentation (2h)
- [ ] Full test suite run
- [ ] Create release notes

**Total Estimated Effort:** 26 hours (3-4 days)

---

## ✅ Success Criteria

### Before Merging to Production:
- [ ] Path traversal security test passes
- [ ] Test pass rate ≥ 95% (660+ of 694 tests)
- [ ] No critical security issues
- [ ] Documentation updated
- [ ] All Phase 3 features working

### Current Metrics:
- **Test Pass Rate:** 66.6% (462/694) → Target: 95%
- **Feature Parity:** 90% → Target: 95%
- **Security Issues:** 1 critical → Target: 0
- **Code Duplication:** 0% ✅

---

## 📞 Who Does What

### Security Team
- Fix path traversal vulnerability
- Re-run security test suite
- Document security controls

### QA Team
- Execute automated import migration
- Fix API compatibility tests
- Run full regression testing

### Development Team
- Complete Phase 3 features
- Code review fixes
- Integration testing

### Documentation Team
- Update all affected docs
- Create migration guides
- Prepare release notes

---

## 🆘 Need Help?

**Questions about:**
- Security fix: See `/docs/VALIDATION_REPORT_2025-10-11.md` Section 7
- Test migration: See `/docs/TEST_MIGRATION_STATUS.md`
- API changes: See `/docs/architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md`
- UI features: See `/docs/GAP_ANALYSIS_UI_API_ALIGNMENT.md`

**Contact:**
- Technical questions: Development team lead
- Security concerns: Security team
- Test issues: QA lead

---

**Last Updated:** October 11, 2025
**Next Review:** After critical security fix
