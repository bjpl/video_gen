# Dependency Management Guide

## Overview

This project uses a two-file approach for Python dependency management:

1. **`requirements.txt`** - High-level dependencies with version ranges
2. **`requirements.lock`** - Exact pinned versions for reproducible builds

## Files

### requirements.txt (Development)

This file contains high-level dependencies with flexible version ranges:

```
# Core dependencies
Pillow>=11.3.0,<12.0.0
matplotlib>=3.9.0
edge-tts>=7.2.3
```

**Use this file for:**
- Local development
- Adding new dependencies
- Understanding project requirements
- Updating dependency versions

### requirements.lock (Production)

This file contains ALL dependencies (including transitive) with exact versions:

```
# All dependencies pinned
Pillow==11.3.0
matplotlib==3.10.7
contourpy==1.3.3
cycler==0.12.1
...
```

**Use this file for:**
- Docker builds (production)
- CI/CD pipelines
- Ensuring reproducible builds
- Deployment to Railway/other platforms

## Workflow

### 1. Adding New Dependencies

1. Add to `requirements.txt` with version range:
   ```bash
   echo "new-package>=1.0.0" >> requirements.txt
   ```

2. Install and test locally:
   ```bash
   pip install -r requirements.txt
   ```

3. Regenerate `requirements.lock`:
   ```bash
   pip freeze > requirements.lock.tmp
   # Then filter to only include relevant packages
   ```

### 2. Updating Dependencies

To update all dependencies to latest compatible versions:

```bash
# 1. Update your local environment
pip install -U -r requirements.txt

# 2. Test thoroughly
pytest tests/

# 3. Regenerate lock file
pip freeze > requirements.lock.tmp

# 4. Review changes
diff requirements.lock requirements.lock.tmp

# 5. Replace if tests pass
mv requirements.lock.tmp requirements.lock
```

### 3. Updating a Single Dependency

```bash
# 1. Update in requirements.txt
# Change: package>=1.0.0
# To:     package>=2.0.0

# 2. Install updated version
pip install -U package

# 3. Test
pytest tests/

# 4. Update lock file
pip freeze > requirements.lock.tmp
mv requirements.lock.tmp requirements.lock
```

### 4. Regenerating requirements.lock

Complete regeneration process:

```bash
# 1. Create a clean virtual environment
python -m venv clean_venv
source clean_venv/bin/activate  # or: clean_venv\Scripts\activate on Windows

# 2. Install from requirements.txt
pip install -r requirements.txt

# 3. Generate lock file
pip freeze > requirements.lock

# 4. Deactivate and remove clean environment
deactivate
rm -rf clean_venv
```

## Docker Integration

The `Dockerfile` uses `requirements.lock` for reproducible builds:

```dockerfile
# Copy requirements and install Python dependencies
# Use requirements.lock for reproducible builds
COPY requirements.lock /tmp/
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r /tmp/requirements.lock
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Install dependencies
  run: |
    python -m pip install --upgrade pip
    pip install -r requirements.lock
```

### Railway Deployment

Railway automatically uses `requirements.lock` when present:

```json
{
  "build": {
    "builder": "NIXPACKS"
  }
}
```

Nixpacks will detect and use `requirements.lock` if it exists, falling back to `requirements.txt` if not.

## Best Practices

### DO:
- ✅ Use `requirements.lock` for all production deployments
- ✅ Regenerate lock file after dependency changes
- ✅ Test thoroughly after updating dependencies
- ✅ Commit both files to version control
- ✅ Review lock file changes in PRs
- ✅ Use version ranges in `requirements.txt`
- ✅ Pin exact versions in `requirements.lock`

### DON'T:
- ❌ Edit `requirements.lock` manually
- ❌ Use `requirements.txt` for production builds
- ❌ Skip testing after dependency updates
- ❌ Ignore dependency security advisories
- ❌ Pin versions too aggressively in `requirements.txt`
- ❌ Use `pip freeze` output directly without filtering

## Dependency Categories

Current dependencies organized by purpose:

### Core Image Processing
- Pillow (image manipulation)
- numpy (numerical operations)

### Video Generation
- moviepy (video editing)
- imageio-ffmpeg (FFmpeg bindings)

### Audio/Text-to-Speech
- edge-tts (neural TTS)

### Web UI
- FastAPI (web framework)
- uvicorn (ASGI server)
- Jinja2 (templates)

### AI Features
- anthropic (Claude API)

### Data Parsing
- PyYAML (YAML parsing)
- requests (HTTP requests)

### Testing
- pytest (test framework)
- pytest-asyncio (async testing)
- pytest-cov (coverage)

## Security Considerations

### Dependency Scanning

Regularly scan for vulnerabilities:

```bash
# Using pip-audit (recommended)
pip install pip-audit
pip-audit -r requirements.lock

# Using safety
pip install safety
safety check -r requirements.lock
```

### Automated Updates

Consider using:
- **Dependabot** (GitHub) - Automated dependency PRs
- **Renovate** - Flexible dependency updates
- **pip-review** - Interactive dependency updates

### Version Pinning Strategy

**requirements.txt:**
```
# Allow patch updates: >=1.2.0,<1.3.0
package>=1.2.0,<1.3.0

# Allow minor updates: >=1.2.0,<2.0.0
package>=1.2.0,<2.0.0

# Exact version (when needed): ==1.2.3
critical-package==1.2.3
```

**requirements.lock:**
```
# ALWAYS exact versions
package==1.2.3
dependency==4.5.6
```

## Troubleshooting

### Issue: "Cannot install package X"

**Solution:**
```bash
# Clear pip cache
pip cache purge

# Reinstall from scratch
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.lock
```

### Issue: "Version conflict between packages"

**Solution:**
```bash
# Check for conflicts
pip check

# Use pipdeptree to visualize
pip install pipdeptree
pipdeptree --warn conflict
```

### Issue: "Docker build fails with dependency error"

**Solution:**
1. Verify `requirements.lock` is up to date
2. Test locally with same Python version
3. Check for platform-specific dependencies
4. Review Docker build logs for specific errors

## Maintenance Schedule

### Weekly
- ✅ Check for security advisories
- ✅ Review automated dependency PR suggestions

### Monthly
- ✅ Update dependencies to latest compatible versions
- ✅ Regenerate `requirements.lock`
- ✅ Run full test suite
- ✅ Deploy to staging for validation

### Quarterly
- ✅ Review all dependencies for necessity
- ✅ Remove unused dependencies
- ✅ Consider major version upgrades
- ✅ Update Python version if needed

## Related Documentation

- [Production Readiness](./PRODUCTION_READINESS.md) - Deployment checklist
- [Docker Configuration](../Dockerfile) - Container build process
- [CI/CD Workflows](../.github/workflows/) - Automated testing

## References

- [pip documentation](https://pip.pypa.io/)
- [Python Packaging User Guide](https://packaging.python.org/)
- [PEP 440 - Version Specifiers](https://peps.python.org/pep-0440/)
- [Railway Deployment Docs](https://docs.railway.app/)
