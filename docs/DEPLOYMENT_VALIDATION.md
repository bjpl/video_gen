# Deployment Validation Checklist

## Pre-Deployment Validation

### System Requirements
- [ ] Python 3.8+ installed
- [ ] Sufficient disk space (2GB+ free)
- [ ] Internet connection available
- [ ] All dependencies in requirements.txt available

### Installation Validation
- [ ] `pip install -r requirements.txt` completes without errors
- [ ] FFmpeg available via imageio-ffmpeg
- [ ] All required scripts present in scripts/

### Directory Structure
- [ ] `inputs/` directory exists
- [ ] `drafts/` directory exists
- [ ] `audio/` directory exists
- [ ] `videos/` directory exists
- [ ] `tests/` directory exists
- [ ] `docs/` directory exists

## Functionality Validation

### 1. Auto-Orchestrator Core

#### CLI Interface
- [ ] `python scripts/create_video_auto.py --help` displays help
- [ ] All command-line options documented
- [ ] Error messages are clear and actionable

#### Argument Validation
- [ ] `--type` is required
- [ ] `--from` required for document/youtube/yaml types
- [ ] Invalid arguments show helpful error messages
- [ ] Missing required args show usage information

### 2. Document Input Processing

#### Basic Document Parsing
- [ ] Markdown files (.md) parse correctly
- [ ] Plain text files (.txt) parse correctly
- [ ] Headers converted to scenes
- [ ] Content extracted accurately

#### Document to YAML Generation
- [ ] YAML file created in `drafts/`
- [ ] YAML contains all required fields:
  - [ ] `title`
  - [ ] `description`
  - [ ] `accent_color`
  - [ ] `scenes` array
- [ ] Each scene contains:
  - [ ] `scene_id`
  - [ ] `scene_type`
  - [ ] `visual_content`
  - [ ] `narration`
  - [ ] `voice`
  - [ ] `min_duration` and `max_duration`

#### Test Cases
- [ ] Small document (< 500 words) processes successfully
- [ ] Medium document (500-2000 words) processes successfully
- [ ] Large document (2000+ words) processes successfully
- [ ] Document with special characters handles correctly
- [ ] Document with code blocks handles correctly
- [ ] Empty sections handled gracefully

### 3. YouTube Input Processing

#### YouTube Search (if API available)
- [ ] Search query returns results
- [ ] Video selection works
- [ ] Transcript fetched successfully

#### YouTube Transcript
- [ ] Transcript API accessible
- [ ] Transcript converted to YAML
- [ ] Timing information preserved
- [ ] Language detection works

#### Test Cases
- [ ] Popular video transcripts fetch successfully
- [ ] Educational content processes correctly
- [ ] Videos without transcripts fail gracefully
- [ ] Private videos handled gracefully

### 4. YAML Input Processing

#### YAML Validation
- [ ] Valid YAML files accepted
- [ ] Invalid YAML rejected with clear error
- [ ] Required fields validated
- [ ] Optional fields handled correctly

#### YAML to Script
- [ ] All scenes processed
- [ ] Scene types recognized
- [ ] Visual content structured correctly
- [ ] Narration text preserved

#### Test Cases
- [ ] Minimal YAML (2 scenes) works
- [ ] Complex YAML (10+ scenes) works
- [ ] All scene types supported:
  - [ ] `title_intro`
  - [ ] `concept`
  - [ ] `code_example`
  - [ ] `comparison`
  - [ ] `timeline`
  - [ ] `quote`
  - [ ] `call_to_action`

### 5. Wizard Mode

#### Interactive Wizard
- [ ] Wizard launches successfully
- [ ] User prompts are clear
- [ ] Input validation works
- [ ] YAML generated correctly

#### Test Cases
- [ ] Complete wizard flow works
- [ ] Wizard can be exited gracefully
- [ ] Invalid inputs handled properly

### 6. Script Generation (Stage 2)

#### YAML to Script Conversion
- [ ] Scripts generated in appropriate directory
- [ ] All scenes included
- [ ] Narration formatted correctly
- [ ] Timing calculations accurate

#### AI Enhancement (Optional)
- [ ] `--use-ai` flag works if API key set
- [ ] Enhanced narration improves quality
- [ ] Falls back gracefully if AI unavailable

#### Test Cases
- [ ] Basic script generation works
- [ ] AI enhancement works (if configured)
- [ ] Long scripts (10+ scenes) generate correctly

### 7. Audio Generation (Stage 3)

#### Audio Synthesis
- [ ] Audio files created in `audio/` directory
- [ ] Each scene has corresponding audio file
- [ ] Audio quality is acceptable
- [ ] Timing information saved

#### Voice Options
- [ ] `male` voice works
- [ ] `male_warm` voice works
- [ ] `female` voice works
- [ ] `female_friendly` voice works

#### Test Cases
- [ ] Short narration (< 30s) generates correctly
- [ ] Long narration (> 2min) generates correctly
- [ ] Multiple scenes processed in sequence
- [ ] Timing JSON file created and accurate

### 8. Video Generation (Stage 4)

#### Video Creation
- [ ] Video files created in `videos/` directory
- [ ] Video contains all scenes
- [ ] Audio synchronized correctly
- [ ] Visual quality acceptable

#### Visual Elements
- [ ] Text readable and clear
- [ ] Colors applied correctly
- [ ] Animations smooth
- [ ] Transitions work properly

#### Test Cases
- [ ] 30-second video generates successfully
- [ ] 2-minute video generates successfully
- [ ] 5-minute video generates successfully
- [ ] All color schemes work:
  - [ ] `blue`
  - [ ] `orange`
  - [ ] `purple`
  - [ ] `green`
  - [ ] `pink`
  - [ ] `cyan`

### 9. End-to-End Integration

#### Complete Workflows
- [ ] Document → Video workflow completes
- [ ] YouTube → Video workflow completes
- [ ] YAML → Video workflow completes
- [ ] Wizard → Video workflow completes

#### Error Recovery
- [ ] Stage failures reported clearly
- [ ] Pipeline stops at failed stage
- [ ] Error messages actionable
- [ ] Partial outputs preserved

#### Performance
- [ ] 30s video completes in < 2 minutes
- [ ] 2min video completes in < 5 minutes
- [ ] Memory usage stays reasonable (< 2GB)
- [ ] CPU usage acceptable

## Error Handling Validation

### Input Errors
- [ ] Nonexistent file → Clear error message
- [ ] Invalid file format → Clear error message
- [ ] Corrupted YAML → Clear error message
- [ ] Empty document → Handled gracefully

### Processing Errors
- [ ] Network failures → Retry or clear error
- [ ] API errors → Handled gracefully
- [ ] Disk full → Clear error message
- [ ] Permission errors → Clear error message

### Edge Cases
- [ ] Very long documents handled
- [ ] Very short documents handled
- [ ] Special characters in filenames
- [ ] Unicode content processed correctly

## Output Validation

### File Outputs
- [ ] YAML files valid and complete
- [ ] Audio files playable
- [ ] Video files playable
- [ ] Timing files accurate

### Quality Checks
- [ ] Narration clear and understandable
- [ ] Visual content readable
- [ ] Audio synchronized with video
- [ ] No artifacts or glitches

### Naming Conventions
- [ ] Files named consistently
- [ ] Timestamps accurate
- [ ] No name collisions

## Documentation Validation

### User Documentation
- [ ] README exists and is current
- [ ] Quick Start guide accurate
- [ ] Deployment guide complete
- [ ] Troubleshooting guide helpful

### Developer Documentation
- [ ] API documentation exists
- [ ] Code comments adequate
- [ ] Architecture documented
- [ ] Test documentation exists

### Examples
- [ ] Example inputs provided
- [ ] Example outputs documented
- [ ] Common workflows documented

## Testing Validation

### Unit Tests
- [ ] All unit tests pass
- [ ] Test coverage > 70%
- [ ] Critical paths tested

### Integration Tests
- [ ] All integration tests pass
- [ ] End-to-end tests pass
- [ ] Real-world scenarios tested

### Test Execution
```bash
# Run all tests
pytest tests/test_auto_orchestrator.py -v

# Expected results:
# - All tests pass
# - No warnings or errors
# - Coverage report generated
```

## Security Validation

### API Keys
- [ ] API keys never in code
- [ ] Environment variables used
- [ ] Keys not logged
- [ ] Keys not in error messages

### File Handling
- [ ] Input validation prevents injection
- [ ] File paths sanitized
- [ ] File size limits enforced
- [ ] Dangerous file types rejected

### Network Security
- [ ] HTTPS used for API calls
- [ ] Credentials never transmitted in clear
- [ ] Timeout protections in place

## Performance Benchmarks

### Processing Times (Target)
- [ ] Document parsing: < 5 seconds
- [ ] Script generation: < 10 seconds
- [ ] Audio generation: < 30 seconds (per minute of audio)
- [ ] Video generation: < 60 seconds (per minute of video)

### Resource Usage (Target)
- [ ] Peak memory: < 2GB
- [ ] CPU usage: < 80% sustained
- [ ] Disk I/O: Reasonable
- [ ] Network usage: Minimal (except TTS)

## Deployment Checklist

### Pre-Deployment
- [ ] All tests passing
- [ ] Documentation complete
- [ ] Dependencies documented
- [ ] Known issues documented

### Deployment
- [ ] Installation instructions work
- [ ] First-time setup works
- [ ] Environment variables configured
- [ ] Permissions correct

### Post-Deployment
- [ ] Test video generated successfully
- [ ] All features working
- [ ] Performance acceptable
- [ ] Monitoring in place

## Sign-Off

### Validation Results

**Date**: _________________

**Validated By**: _________________

**Version**: _________________

### Checklist Summary

- **Total Checks**: _____ / _____
- **Passed**: _____
- **Failed**: _____
- **N/A**: _____

### Critical Issues

List any critical issues that must be resolved before production:

1. _______________________________________________
2. _______________________________________________
3. _______________________________________________

### Minor Issues

List any minor issues that can be resolved post-deployment:

1. _______________________________________________
2. _______________________________________________
3. _______________________________________________

### Deployment Recommendation

- [ ] **APPROVED** - Ready for production deployment
- [ ] **APPROVED WITH CONDITIONS** - Deploy with noted issues
- [ ] **NOT APPROVED** - Critical issues must be resolved

### Notes

_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

### Sign-Off

**Technical Lead**: _________________ Date: _________

**QA Lead**: _________________ Date: _________

**Product Owner**: _________________ Date: _________

---

## Quick Validation Script

Save this as `scripts/validate_deployment.sh`:

```bash
#!/bin/bash

echo "=== Deployment Validation ==="
echo ""

echo "[1/5] Checking Python version..."
python --version || exit 1

echo "[2/5] Checking dependencies..."
pip list | grep -E "Pillow|edge-tts|numpy|PyYAML" || exit 1

echo "[3/5] Checking auto-orchestrator..."
python scripts/create_video_auto.py --help > /dev/null || exit 1

echo "[4/5] Running tests..."
pytest tests/test_auto_orchestrator.py -q || exit 1

echo "[5/5] Creating test video..."
echo "# Test" > /tmp/test_deploy.md
python scripts/create_video_auto.py --from /tmp/test_deploy.md --type document --auto || exit 1

echo ""
echo "✓ Deployment validation PASSED"
echo ""
```

Run with:
```bash
bash scripts/validate_deployment.sh
```
