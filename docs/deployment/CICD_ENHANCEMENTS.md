# CI/CD Pipeline Enhancements

**Project**: video_gen - Professional Video Generation System
**Version**: 2.0.0
**Date**: October 16, 2025

---

## Current CI/CD Status

**Existing Workflows** (in `.github/workflows/`):
- ✅ `test.yml` - Fast tests on push/PR
- ✅ `coverage.yml` - Comprehensive coverage reports
- ✅ `lint.yml` - Code quality checks

**New Workflows** (created):
- ✅ `deploy-staging.yml` - Automated staging deployment
- ✅ `deploy-production.yml` - Production deployment with safeguards

---

## Workflow Architecture

### Test Workflow (existing)

**Triggers**:
- Push to `main` branch
- Pull requests to `main`

**Features**:
- Fast tests only (`-m "not slow"`)
- 75% coverage requirement
- 5-minute timeout
- Pip caching for speed
- Coverage reports to PR comments
- Test result artifacts

### Coverage Workflow (existing)

**Triggers**:
- Push to `main`
- Pull requests
- Manual dispatch

**Features**:
- All tests (including slow)
- Detailed coverage reports
- Branch coverage analysis
- Codecov integration
- 90-day report retention

### Staging Deployment Workflow (new)

**Triggers**:
- Push to `staging` or `develop` branches
- Manual dispatch with environment selection

**Pipeline Stages**:

1. **Test Stage**:
   - Run fast tests
   - Verify 75% coverage
   - Upload test results

2. **Deploy Stage**:
   - SSH to staging server
   - Pull latest code
   - Update dependencies
   - Run tests on server
   - Restart service
   - Verify health

3. **Verification Stage**:
   - Health check
   - Smoke tests (all endpoints)
   - Slack notification

4. **Rollback Stage** (on failure):
   - Automatic rollback to previous commit
   - Service restart
   - Notification

### Production Deployment Workflow (new)

**Triggers**:
- Push to `main` branch
- Version tags (`v*.*.*`)
- Manual dispatch (requires "DEPLOY" confirmation)

**Pipeline Stages**:

1. **Pre-Deployment Checks**:
   - Comprehensive test suite
   - Security scans (safety, bandit)
   - Coverage validation (75%)
   - Configuration validation
   - No hardcoded secrets check

2. **Backup Stage**:
   - Create application backup
   - Backup environment files
   - Maintain 5 most recent backups

3. **Deploy Stage**:
   - Record current commit (for rollback)
   - Pull latest code
   - Update dependencies
   - Run smoke tests
   - Zero-downtime restart
   - Health verification (5 attempts)

4. **Verification Stage**:
   - Comprehensive health check
   - Smoke test all endpoints
   - Create deployment tag
   - Success notification

5. **Post-Deployment Monitoring**:
   - Performance baseline test
   - 5-minute stability monitoring
   - Generate deployment report

6. **Rollback Stage** (on failure):
   - Restore previous commit
   - Reinstall dependencies
   - Restart service
   - Verify rollback success
   - Critical notification

---

## Required GitHub Secrets

### Staging Environment

```bash
# SSH Configuration
STAGING_SSH_KEY        # Private SSH key for staging server
STAGING_HOST           # Staging server hostname/IP
STAGING_USER           # SSH user (e.g., video-gen)

# Notifications
SLACK_WEBHOOK          # Slack webhook URL for notifications
```

### Production Environment

```bash
# SSH Configuration
PRODUCTION_SSH_KEY     # Private SSH key for production server
PRODUCTION_HOST        # Production server hostname/IP
PRODUCTION_USER        # SSH user (e.g., www-data)

# Optional
CODECOV_TOKEN          # Codecov integration token
```

### Setting Secrets in GitHub

```bash
# Navigate to repository settings
# Settings → Secrets and variables → Actions → New repository secret

# Or use GitHub CLI
gh secret set STAGING_SSH_KEY < ~/.ssh/id_rsa_staging
gh secret set STAGING_HOST -b "staging.your-domain.com"
gh secret set STAGING_USER -b "video-gen"
gh secret set SLACK_WEBHOOK -b "https://hooks.slack.com/services/..."
```

---

## SSH Key Setup

### Generate SSH Keys

```bash
# For staging
ssh-keygen -t ed25519 -C "github-actions-staging" -f ~/.ssh/github_actions_staging

# For production
ssh-keygen -t ed25519 -C "github-actions-production" -f ~/.ssh/github_actions_production
```

### Add Public Keys to Servers

**Staging Server**:
```bash
# Copy public key to staging
ssh-copy-id -i ~/.ssh/github_actions_staging.pub video-gen@staging.your-domain.com

# Or manually
ssh video-gen@staging.your-domain.com
mkdir -p ~/.ssh
chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys
# Paste public key, save
chmod 600 ~/.ssh/authorized_keys
```

**Production Server**:
```bash
# Copy public key to production
ssh-copy-id -i ~/.ssh/github_actions_production.pub www-data@your-domain.com
```

### Add Private Keys to GitHub Secrets

```bash
# Staging
gh secret set STAGING_SSH_KEY < ~/.ssh/github_actions_staging

# Production
gh secret set PRODUCTION_SSH_KEY < ~/.ssh/github_actions_production
```

---

## Deployment Process

### Staging Deployment

**Automatic** (on push to staging/develop):
```bash
# 1. Create/checkout staging branch
git checkout -b staging

# 2. Make changes and commit
git add .
git commit -m "feat: new feature"

# 3. Push to trigger deployment
git push origin staging

# 4. GitHub Actions automatically:
#    - Runs tests
#    - Deploys to staging
#    - Verifies health
#    - Runs smoke tests
#    - Sends Slack notification
```

**Manual**:
```bash
# Use GitHub web interface
# Actions → Deploy to Staging → Run workflow
# Select branch and environment
```

### Production Deployment

**From Main Branch** (automatic):
```bash
# 1. Merge to main (via PR)
git checkout main
git pull origin main
git merge staging

# 2. Push to trigger deployment
git push origin main

# 3. GitHub Actions automatically:
#    - Runs comprehensive tests
#    - Security scans
#    - Creates backup
#    - Deploys to production
#    - Verifies deployment
#    - Monitors for 5 minutes
#    - Creates deployment tag
```

**Manual** (with confirmation):
```bash
# Use GitHub web interface
# Actions → Deploy to Production → Run workflow
# Type "DEPLOY" to confirm
# Workflow runs with all safety checks
```

**Version Tag** (automatic):
```bash
# Create version tag
git tag -a v2.0.1 -m "Release v2.0.1"
git push origin v2.0.1

# Triggers production deployment
```

---

## Branch Protection Rules

### Recommended Configuration

**Main Branch**:
```yaml
Protection rules:
  - Require pull request reviews (1 approver)
  - Require status checks to pass:
    - test
    - coverage
    - lint
  - Require branches to be up to date
  - Require conversation resolution
  - Require signed commits (optional)
  - Include administrators: No
```

**Staging Branch**:
```yaml
Protection rules:
  - Require status checks to pass:
    - test
  - Allow force pushes: Yes (for testing)
```

### Setting Up in GitHub

```bash
# Via GitHub CLI
gh api repos/:owner/:repo/branches/main/protection \
  -X PUT \
  -F required_status_checks='{"strict":true,"contexts":["test","coverage"]}' \
  -F enforce_admins=false \
  -F required_pull_request_reviews='{"required_approving_review_count":1}'
```

---

## Monitoring CI/CD

### GitHub Actions Dashboard

**Access**:
- Repository → Actions tab
- View workflow runs
- Check logs for each step
- Download artifacts

**Notifications**:
- GitHub notifications (default)
- Slack (configured in workflows)
- Email (GitHub settings)

### Slack Integration

**Setup Slack Webhook**:
```bash
# 1. Go to Slack workspace
# 2. Add "Incoming Webhooks" app
# 3. Create webhook for channel (e.g., #deployments)
# 4. Copy webhook URL
# 5. Add to GitHub secrets:
gh secret set SLACK_WEBHOOK -b "https://hooks.slack.com/services/..."
```

**Notification Examples**:
- ✅ Staging deployment successful
- ❌ Production deployment failed - rolling back
- ⚠️ Rollback completed
- 🚀 Production deployment successful

### Failed Deployment Response

**When Staging Fails**:
1. Check GitHub Actions logs
2. Review error message
3. Fix issue locally
4. Push fix
5. Automatic retry

**When Production Fails**:
1. Automatic rollback initiated
2. Slack notification sent
3. Check rollback success
4. Review failure logs
5. Fix issue
6. Test in staging
7. Retry production deployment

---

## Performance Optimization

### Speed Improvements

**Caching Strategy**:
```yaml
# In workflows
- name: Cache pip
  uses: actions/cache@v4
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}

# Cache Python setup
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.10'
    cache: 'pip'  # Automatic caching
```

**Parallel Jobs**:
```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11']  # Test multiple versions
      fail-fast: false  # Continue even if one fails
```

**Fast Tests in CI**:
```bash
# Only run fast tests in CI
pytest -m "not slow"

# Slow tests in nightly builds or coverage workflow
pytest  # All tests
```

---

## Security Best Practices

### Secret Management

**Never Commit**:
- SSH private keys
- API keys
- Passwords
- Tokens
- `.env` files

**Use GitHub Secrets**:
- All sensitive values
- Environment-specific configs
- Rotation: Update secrets regularly

### Code Scanning

**Enabled in Workflows**:
```yaml
- name: Security scan
  run: |
    pip install safety bandit
    safety check
    bandit -r video_gen app
```

**Tools**:
- `safety`: Dependency vulnerabilities
- `bandit`: Code security issues
- `pip-audit`: Python package audit

### Deployment Safety

**Pre-Deployment Checks**:
- All tests must pass
- Coverage threshold met (75%)
- No security vulnerabilities
- No hardcoded secrets
- Configuration validated

**Production Safeguards**:
- Manual confirmation required
- Automatic backup before deploy
- Health checks after deploy
- Automatic rollback on failure
- 5-minute monitoring period

---

## Maintenance

### Regular Tasks

**Weekly**:
- Review failed workflow runs
- Check workflow execution times
- Verify backup integrity
- Update dependencies (if needed)

**Monthly**:
- Review and rotate secrets
- Update GitHub Actions versions
- Check for new security best practices
- Optimize workflow performance

**Quarterly**:
- Full CI/CD pipeline audit
- Security scan of infrastructure
- Review deployment procedures
- Update documentation

### Troubleshooting

**Workflow Fails to Start**:
- Check branch protection rules
- Verify workflow syntax (YAML)
- Check GitHub status
- Review repository permissions

**Deployment Fails**:
- Check SSH connectivity
- Verify server has space
- Check service status
- Review deployment logs

**Slow Workflows**:
- Enable caching
- Use fast tests for PRs
- Parallelize where possible
- Optimize test suite

---

## Future Enhancements

### Recommended Additions

**Blue-Green Deployment**:
```yaml
# Deploy to blue environment
# Run tests on blue
# Switch traffic to blue
# Keep green as fallback
```

**Canary Deployment**:
```yaml
# Deploy to 10% of servers
# Monitor for 30 minutes
# Gradually increase to 100%
```

**Advanced Monitoring**:
```yaml
# Integration with:
# - Datadog
# - New Relic
# - Sentry
# - PagerDuty
```

**Automated Performance Testing**:
```yaml
# Run k6 load tests
# Compare with baseline
# Fail if regression detected
```

---

## Summary

**CI/CD Status**: ✅ **PRODUCTION READY**

**Features Implemented**:
- ✅ Automated testing on all PRs
- ✅ Coverage enforcement (75%)
- ✅ Staging deployment automation
- ✅ Production deployment with safeguards
- ✅ Automatic rollback on failure
- ✅ Slack notifications
- ✅ Security scanning
- ✅ Post-deployment monitoring

**Safety Features**:
- Pre-deployment testing
- Automatic backups
- Health verification
- Automatic rollback
- Manual confirmation for production

**Next Steps**:
1. Configure GitHub secrets
2. Set up SSH keys
3. Test staging deployment
4. Configure Slack webhook
5. Set branch protection rules
6. Deploy to production

---

**Document Version**: 1.0
**Last Updated**: October 16, 2025
**Status**: ✅ READY FOR IMPLEMENTATION
