# Quick Cleanup Actions - Video Gen Project

**Ready-to-execute commands for immediate cleanup wins**

---

## 🚀 Quick Start (5 minutes)

Execute these commands in sequence for immediate cleanup:

```bash
cd /c/Users/brand/Development/Project_Workspace/active-development/video_gen

# 1. Remove deprecated scripts (SAFE)
rm -f scripts/_deprecated_generate_all_videos_unified_v2.py
rm -f scripts/_deprecated_generate_video_set.py

# 2. Clean Python cache (SAFE)
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete

# 3. Remove build artifacts (SAFE)
rm -f .coverage coverage.json test_results.txt VALIDATION_COMPLETE.txt

# 4. Verify git status
git status
```

**Result:** ~15 files removed, 14 directories cleaned, zero risk.

---

## 📦 Organize Root Directory (15 minutes)

### Step 1: Create directories
```bash
mkdir -p docs/reports docs/guides docs/status
```

### Step 2: Move implementation reports
```bash
# Move all implementation/delivery reports
for file in COMPLETE_ALL_PHASES.md COMPLETE_FIX_SUMMARY.md \
            COMPLETE_SYSTEM_SUMMARY.md FINAL_COMPLETE_IMPLEMENTATION.md \
            FINAL_IMPLEMENTATION_SUMMARY.md FULL_INTEGRATION_VERIFIED.md \
            IMPLEMENTATION_COMPLETE.md VALIDATION_REPORT.md \
            AUTO_ORCHESTRATOR_DELIVERY.md TEMPLATE_SYSTEM_DELIVERY.md \
            EDUCATIONAL_IMPLEMENTATION_COMPLETE.md \
            MULTILINGUAL_IMPLEMENTATION_COMPLETE.md; do
    [ -f "$file" ] && git mv "$file" docs/reports/ 2>/dev/null || true
done
```

### Step 3: Move user guides
```bash
# Move all user-facing guides
for file in CONTENT_CONTROL_GUIDE.md EDUCATIONAL_CONTENT_ANALYSIS.md \
            EDUCATIONAL_SCENES_GUIDE.md EDUCATIONAL_SCENES_QUICKREF.md \
            MULTILINGUAL_GUIDE.md MULTILINGUAL_QUICKREF.md \
            MULTILINGUAL_QUICKSTART.md PROGRAMMATIC_GUIDE.md \
            PROGRAMMATIC_COMPLETE.md PARSE_RAW_CONTENT.md \
            AI_NARRATION_QUICKSTART.md WEB_UI_QUICKSTART.md; do
    [ -f "$file" ] && git mv "$file" docs/guides/ 2>/dev/null || true
done
```

### Step 4: Move status files
```bash
# Move status reports
for file in STATUS_SUMMARY.md WEB_UI_STATUS.md; do
    [ -f "$file" ] && git mv "$file" docs/status/ 2>/dev/null || true
done
```

### Step 5: Delete redundant files
```bash
# Remove files redundant with START_HERE.md and README.md
rm -f READY_TO_USE.md TRY_NOW.md QUICK_START.md \
      QUICK_REFERENCE.md QUICK_WIN_AUTO_ORCHESTRATOR.md \
      NEW_WORKFLOW_GUIDE.md DIRECTORY_STRUCTURE.md
```

**Result:** 38 → 5 root MD files (87% reduction)

---

## 🔧 Fix Unused Imports (10 minutes)

### Install autoflake
```bash
pip install autoflake
```

### Dry run (review changes)
```bash
autoflake --remove-all-unused-imports --recursive --check .
```

### Apply changes
```bash
autoflake --remove-all-unused-imports --recursive --in-place \
    scripts/ video_gen/ app/ tests/
```

**Result:** 100+ unused imports removed

---

## 📋 Update .gitignore (2 minutes)

Add to `.gitignore`:

```bash
cat >> .gitignore << 'EOF'

# Coverage and testing
.coverage
coverage.json
.coverage.*
htmlcov/
.pytest_cache/
*.cover
.hypothesis/
test_results.txt

# Build artifacts
*.log

# Outputs (keep README)
output/
!output/README.md

# Status directories
status/
archive/

# IDE
.vscode/settings.json
.idea/workspace.xml

EOF
```

---

## 🎯 Files to Review Manually

These require human judgment before deletion:

### 1. app/main_backup.py (762 lines)
```bash
# Compare with current main.py
diff app/main_backup.py app/main.py

# If identical or outdated, delete:
rm app/main_backup.py
```

### 2. Meta-generation scripts (5 files)
```bash
# Review which are actively used:
ls -lh scripts/generate_meta*.py scripts/meta_docs*.py

# Likely keep only:
# - generate_meta_videos_final.py (if used)
# Delete rest after confirming
```

### 3. scripts/generate_3_meta_videos.py
```bash
# Check if used anywhere:
grep -r "generate_3_meta_videos" .

# If not used and broken, delete:
rm scripts/generate_3_meta_videos.py
```

---

## ✅ Verification

After cleanup, verify system still works:

```bash
# Run tests
python -m pytest tests/

# Try basic video generation
cd scripts
python create_video_auto.py --help

# Check git status
git status

# Count remaining root files
ls -1 *.md | wc -l  # Should be ~5
```

---

## 📊 Expected Results

### Before Cleanup:
```
Root directory:   38 MD files
Unused imports:   100+ instances
Cache dirs:       14 __pycache__ directories
Deprecated:       2 scripts, 1 backup file
Temporary:        229KB (drafts/, archive/, status/)
```

### After Cleanup:
```
Root directory:   5 MD files (README, START_HERE, INDEX, GETTING_STARTED, CHANGELOG)
Unused imports:   0 (cleaned by autoflake)
Cache dirs:       0 (all gitignored)
Deprecated:       0 (deleted)
Temporary:        In .gitignore
```

### Benefits:
- ✅ 87% less root clutter
- ✅ Cleaner git diffs
- ✅ Faster navigation
- ✅ Better documentation hierarchy
- ✅ Improved code quality

---

## 🚨 Rollback Plan

If something breaks:

```bash
# View recent changes
git status
git diff

# Undo specific file
git checkout -- path/to/file

# Undo all changes
git reset --hard HEAD

# Restore from backup (if you made one)
cp -r ../video_gen_backup/* .
```

---

## 📝 One-Command Full Cleanup

**WARNING:** Review changes before running this all-at-once command.

```bash
#!/bin/bash
# Save as: cleanup_all.sh

cd /c/Users/brand/Development/Project_Workspace/active-development/video_gen

# Create backup
echo "Creating backup..."
cd ..
cp -r video_gen video_gen_backup_$(date +%Y%m%d_%H%M%S)
cd video_gen

# Execute all cleanup steps
echo "Removing deprecated files..."
rm -f scripts/_deprecated_*.py

echo "Cleaning cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete

echo "Removing artifacts..."
rm -f .coverage coverage.json test_results.txt VALIDATION_COMPLETE.txt

echo "Organizing docs..."
mkdir -p docs/reports docs/guides docs/status

# Move files (add your mv commands here)

echo "Cleanup complete! Run 'git status' to review."
```

---

## 🎯 Recommended Order

1. **Day 1 (30 min):** Quick Start + .gitignore
2. **Day 2 (30 min):** Organize root directory
3. **Day 3 (30 min):** Fix unused imports + manual reviews
4. **Day 4 (30 min):** Verify, test, commit

---

**Created:** October 5, 2025
**For:** video_gen project cleanup
**See also:** docs/CLEANUP_ANALYSIS_REPORT.md (full details)
