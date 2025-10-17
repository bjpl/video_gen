# Staging Environment Deployment Guide

**Project**: video_gen - Professional Video Generation System
**Version**: 2.0.0
**Date**: October 16, 2025

---

## Overview

This guide provides complete instructions for setting up a staging environment that mirrors production, enabling safe testing before production deployment.

---

## Staging Environment Purpose

### Why Staging?

**Testing Requirements**:
- ✅ Test deployment procedures
- ✅ Validate configuration changes
- ✅ Verify updates before production
- ✅ Performance testing under load
- ✅ Integration testing with external services

**Risk Mitigation**:
- Catch deployment issues before production
- Test rollback procedures safely
- Validate SSL/security configurations
- Verify backup and restore procedures

---

## Staging vs Production

### Environment Comparison

| Aspect | Staging | Production |
|--------|---------|------------|
| **Purpose** | Testing, validation | Live user traffic |
| **Data** | Test/synthetic | Real user data |
| **Resources** | Can be smaller | Full size |
| **Uptime** | Can have downtime | High availability |
| **Monitoring** | Basic | Comprehensive |
| **Access** | Team only | Public (or customers) |
| **API Keys** | Test keys | Production keys |
| **Domain** | staging.domain.com | domain.com |

### Resource Requirements

**Minimum Staging Server**:
- CPU: 2 cores (vs 4 for production)
- RAM: 4GB (vs 8GB for production)
- Storage: 20GB (vs 50GB+ for production)
- Network: Standard bandwidth

**Cost Optimization**:
- Use smaller instance sizes
- Can be shut down when not in use
- Share resources if possible
- Use spot instances if available

---

## Setup Instructions

### 1. Server Provisioning

**Option A: Cloud Provider** (Recommended)

```bash
# Example: DigitalOcean Droplet
# Create via dashboard or API
# Specs: 2 vCPU, 4GB RAM, 50GB SSD
# Ubuntu 22.04 LTS
```

**Option B: Local VM** (Development)

```bash
# Using Vagrant
vagrant init ubuntu/jammy64
vagrant up
vagrant ssh
```

**Option C: Docker** (Simplified)

```bash
# Using docker-compose
docker-compose -f docker-compose.staging.yml up -d
```

### 2. Initial Server Setup

**Step 1: Update System**
```bash
# Update package lists
sudo apt-get update
sudo apt-get upgrade -y

# Install essential tools
sudo apt-get install -y git curl wget vim htop
```

**Step 2: Create Application User**
```bash
# Create user for application
sudo useradd -m -s /bin/bash video-gen
sudo usermod -aG sudo video-gen

# Set up SSH access (optional)
sudo mkdir -p /home/video-gen/.ssh
sudo cp ~/.ssh/authorized_keys /home/video-gen/.ssh/
sudo chown -R video-gen:video-gen /home/video-gen/.ssh
sudo chmod 700 /home/video-gen/.ssh
sudo chmod 600 /home/video-gen/.ssh/authorized_keys
```

**Step 3: Install Dependencies**
```bash
# Python 3.10+
sudo apt-get install -y python3.10 python3.10-venv python3-pip

# FFmpeg (required)
sudo apt-get install -y ffmpeg

# Nginx (web server)
sudo apt-get install -y nginx

# Certbot (SSL)
sudo apt-get install -y certbot python3-certbot-nginx
```

### 3. Application Deployment

**Step 1: Clone Repository**
```bash
# Switch to application user
sudo su - video-gen

# Clone repository
cd /home/video-gen
git clone https://github.com/your-org/video_gen.git
cd video_gen

# Checkout specific branch (if needed)
git checkout staging  # or main
```

**Step 2: Set Up Python Environment**
```bash
# Create virtual environment
python3.10 -m venv venv

# Activate environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

**Step 3: Configure Environment**
```bash
# Copy example environment file
cp .env.example .env

# Edit with staging-specific values
nano .env
```

**Staging .env Configuration**:
```bash
# Staging Environment Configuration

# AI API Keys (use test/staging keys if available)
ANTHROPIC_API_KEY=sk-ant-api03-staging-key-here

# Web UI Configuration (different port to avoid conflicts)
API_HOST=0.0.0.0
API_PORT=8002

# Staging-specific settings
DEBUG=false  # Keep false even in staging
LOG_LEVEL=INFO  # Can use DEBUG for troubleshooting

# Output directories
OUTPUT_DIR=/home/video-gen/video_gen/output
AUDIO_DIR=/home/video-gen/video_gen/audio
VIDEO_DIR=/home/video-gen/video_gen/videos

# Staging-specific defaults
DEFAULT_ACCENT_COLOR=blue
DEFAULT_VOICE=male

# Performance settings (can be more relaxed)
MAX_CONCURRENT_JOBS=2
```

**Step 4: Create Required Directories**
```bash
# Create output directories
mkdir -p output/logs output/videos output/audio
mkdir -p user_data

# Set permissions
chmod 755 output output/logs output/videos output/audio
```

**Step 5: Run Tests**
```bash
# Verify setup by running tests
pytest tests/ -m "not slow" -q

# Should see: X passed, Y skipped
# If tests fail, check dependencies and configuration
```

### 4. Service Configuration

**Step 1: Create Systemd Service**

Create `/etc/systemd/system/video-gen-staging.service`:

```ini
[Unit]
Description=Video Generation System (Staging)
After=network.target

[Service]
Type=simple
User=video-gen
Group=video-gen
WorkingDirectory=/home/video-gen/video_gen
Environment="PATH=/home/video-gen/video_gen/venv/bin"
Environment="ENVIRONMENT=staging"
ExecStart=/home/video-gen/video_gen/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8002 --workers 1
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=video-gen-staging

[Install]
WantedBy=multi-user.target
```

**Step 2: Enable and Start Service**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable video-gen-staging

# Start service
sudo systemctl start video-gen-staging

# Check status
sudo systemctl status video-gen-staging

# View logs
sudo journalctl -u video-gen-staging -f
```

### 5. Nginx Configuration

**Step 1: Create Nginx Site Configuration**

Create `/etc/nginx/sites-available/video-gen-staging`:

```nginx
# Staging environment for video_gen
# No SSL initially - add after testing

server {
    listen 80;
    server_name staging.your-domain.com;

    # Logging
    access_log /var/log/nginx/video-gen-staging-access.log;
    error_log /var/log/nginx/video-gen-staging-error.log;

    # Proxy to application
    location / {
        proxy_pass http://127.0.0.1:8002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for SSE)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    # Static files
    location /static/ {
        alias /home/video-gen/video_gen/app/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    # Health check endpoint
    location /api/health {
        proxy_pass http://127.0.0.1:8002;
        access_log off;  # Don't log health checks
    }

    # Max upload size
    client_max_body_size 100M;

    # Staging banner (optional)
    add_header X-Environment "staging" always;
}
```

**Step 2: Enable Site and Restart Nginx**
```bash
# Create symlink to enable site
sudo ln -s /etc/nginx/sites-available/video-gen-staging /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

**Step 3: Configure DNS**
```bash
# Add DNS A record for staging subdomain
# staging.your-domain.com -> <staging-server-ip>

# Verify DNS
dig staging.your-domain.com
# or
nslookup staging.your-domain.com
```

### 6. SSL Configuration (Let's Encrypt)

**Step 1: Obtain SSL Certificate**
```bash
# Use certbot for automatic SSL setup
sudo certbot --nginx -d staging.your-domain.com

# Follow prompts:
# - Enter email for renewal notifications
# - Agree to Terms of Service
# - Choose whether to redirect HTTP to HTTPS (recommended: yes)
```

**Step 2: Verify SSL**
```bash
# Test SSL configuration
curl -I https://staging.your-domain.com/api/health

# Should see:
# HTTP/2 200
# content-type: application/json
```

**Step 3: Test Auto-Renewal**
```bash
# Dry run renewal
sudo certbot renew --dry-run

# Should complete successfully
```

### 7. Firewall Configuration

**Step 1: Configure UFW**
```bash
# Enable UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

---

## Verification and Testing

### 1. Smoke Tests

**Basic Connectivity**:
```bash
# Health check (local)
curl http://localhost:8002/api/health

# Health check (remote)
curl https://staging.your-domain.com/api/health

# Should return:
# {
#   "status": "healthy",
#   "service": "video-generation",
#   "pipeline": "unified",
#   "version": "2.0.0",
#   ...
# }
```

**UI Pages**:
```bash
# Index page
curl https://staging.your-domain.com/ | grep -i "video generation"

# Builder page
curl https://staging.your-domain.com/builder | grep -i "scene builder"

# Should return HTML content
```

**API Endpoints**:
```bash
# Scene types
curl https://staging.your-domain.com/api/scene-types

# Voices
curl https://staging.your-domain.com/api/voices

# Colors
curl https://staging.your-domain.com/api/colors

# Languages
curl https://staging.your-domain.com/api/languages

# All should return JSON with expected data
```

### 2. Integration Tests

**Document Processing Test**:
```bash
# 1. Create test document
cat > test_document.md << 'EOF'
# Test Video

This is a test document for staging validation.

## Section 1

Some content here.

## Section 2

More content here.
EOF

# 2. Upload via API (requires curl with proper JSON)
curl -X POST https://staging.your-domain.com/api/parse/document \
  -H "Content-Type: application/json" \
  -d '{
    "content": "test_document.md",
    "accent_color": "blue",
    "voice": "male",
    "video_count": 1
  }'

# Should return task_id
```

**Video Generation Test**:
```bash
# Create simple video set
curl -X POST https://staging.your-domain.com/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "set_id": "test-001",
    "set_name": "Staging Test",
    "videos": [{
      "video_id": "test-video-001",
      "title": "Test Video",
      "scenes": [{
        "type": "title",
        "title": "Staging Test",
        "subtitle": "Video Generation System"
      }],
      "voice": "male"
    }],
    "accent_color": "blue"
  }'

# Should return task_id
```

**Monitor Task Progress**:
```bash
# Get task status (replace TASK_ID)
curl https://staging.your-domain.com/api/tasks/TASK_ID

# Should show progress and status
```

### 3. Load Testing (Optional)

**Using Apache Bench** (simple):
```bash
# Install ab
sudo apt-get install apache2-utils

# Test health endpoint
ab -n 1000 -c 10 https://staging.your-domain.com/api/health

# Review results:
# - Requests per second
# - Time per request
# - Failed requests (should be 0)
```

**Using k6** (advanced):
```bash
# Install k6
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Create test script
cat > load_test.js << 'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '1m', target: 10 },  // Ramp up to 10 users
    { duration: '3m', target: 10 },  // Stay at 10 users
    { duration: '1m', target: 0 },   // Ramp down
  ],
};

export default function() {
  let response = http.get('https://staging.your-domain.com/api/health');
  check(response, {
    'is status 200': (r) => r.status === 200,
    'is healthy': (r) => r.json('status') === 'healthy',
  });
  sleep(1);
}
EOF

# Run test
k6 run load_test.js
```

---

## Staging-Specific Operations

### Deploying Updates

**Standard Update Procedure**:
```bash
# 1. Connect to staging server
ssh video-gen@staging.your-domain.com

# 2. Navigate to application
cd /home/video-gen/video_gen

# 3. Pull latest changes
git fetch origin
git pull origin main  # or specific branch

# 4. Activate venv
source venv/bin/activate

# 5. Update dependencies (if changed)
pip install -r requirements.txt

# 6. Run tests
pytest tests/ -m "not slow" -q

# 7. Restart service
sudo systemctl restart video-gen-staging

# 8. Verify
curl https://staging.your-domain.com/api/health

# 9. Check logs
sudo journalctl -u video-gen-staging -f --lines=50
```

**Rollback Procedure**:
```bash
# 1. Find previous working commit
git log --oneline -10

# 2. Checkout previous version
git checkout <commit-hash>

# 3. Restart service
sudo systemctl restart video-gen-staging

# 4. Verify
curl https://staging.your-domain.com/api/health
```

### Data Management

**Clearing Test Data**:
```bash
# Stop service
sudo systemctl stop video-gen-staging

# Clear output directories
rm -rf /home/video-gen/video_gen/output/videos/*
rm -rf /home/video-gen/video_gen/output/audio/*

# Keep logs (or clear old ones)
find /home/video-gen/video_gen/output/logs -name "*.log" -mtime +7 -delete

# Restart service
sudo systemctl start video-gen-staging
```

**Backup Staging Data** (before major changes):
```bash
# Create backup
tar -czf staging-backup-$(date +%Y%m%d).tar.gz \
  /home/video-gen/video_gen/output \
  /home/video-gen/video_gen/.env \
  /home/video-gen/video_gen/user_data

# Store backup
mv staging-backup-*.tar.gz /home/video-gen/backups/
```

### Monitoring

**System Monitoring**:
```bash
# Disk usage
df -h

# Memory usage
free -h

# CPU usage
top

# Service status
sudo systemctl status video-gen-staging

# Application logs
sudo journalctl -u video-gen-staging --since "1 hour ago"
```

**Application Monitoring**:
```bash
# Nginx access logs
sudo tail -f /var/log/nginx/video-gen-staging-access.log

# Nginx error logs
sudo tail -f /var/log/nginx/video-gen-staging-error.log

# Application logs
tail -f /home/video-gen/video_gen/output/logs/video_gen.log
```

---

## Testing Deployment Procedures

### Pre-Production Validation

**Checklist Before Production**:
1. [ ] All staging tests passing
2. [ ] Performance acceptable under load
3. [ ] SSL certificate working correctly
4. [ ] All API endpoints functional
5. [ ] Error handling working as expected
6. [ ] Logging properly configured
7. [ ] Backup/restore procedures tested
8. [ ] Rollback procedure tested
9. [ ] Monitoring/alerting functional
10. [ ] Documentation updated

### Deployment Rehearsal

**Full Deployment Test**:
```bash
# 1. Document current state
git rev-parse HEAD > deployment-start-commit.txt
curl https://staging.your-domain.com/api/health > pre-deployment-health.json

# 2. Perform deployment (follow production checklist)
# ... deployment steps ...

# 3. Run comprehensive tests
pytest tests/ -v

# 4. Smoke test all endpoints
./scripts/smoke_test.sh  # Create this script

# 5. Verify health
curl https://staging.your-domain.com/api/health

# 6. Test rollback
git checkout $(cat deployment-start-commit.txt)
sudo systemctl restart video-gen-staging
curl https://staging.your-domain.com/api/health

# 7. Document results
echo "Deployment rehearsal completed: $(date)" >> deployment-rehearsals.log
```

---

## Differences from Production

### Configuration Differences

**Staging-Specific Settings**:
```bash
# .env (staging)
ENVIRONMENT=staging
API_PORT=8002
LOG_LEVEL=INFO  # Can be DEBUG
MAX_CONCURRENT_JOBS=2  # Lower than production
OUTPUT_DIR=/home/video-gen/video_gen/output
```

**Production Settings**:
```bash
# .env (production)
ENVIRONMENT=production
API_PORT=8000
LOG_LEVEL=INFO  # Always INFO
MAX_CONCURRENT_JOBS=4  # Higher for production
OUTPUT_DIR=/var/www/video_gen/output
```

### Resource Allocation

| Resource | Staging | Production |
|----------|---------|------------|
| Workers | 1 | 2-4 |
| Memory | 4GB | 8GB+ |
| CPU | 2 cores | 4+ cores |
| Storage | 20GB | 50GB+ |
| Concurrent Jobs | 2 | 4+ |

---

## Troubleshooting

### Common Issues

**Issue 1: Service Won't Start**
```bash
# Check logs
sudo journalctl -u video-gen-staging -n 50

# Check configuration
source /home/video-gen/video_gen/venv/bin/activate
cd /home/video-gen/video_gen
python -c "from app.main import app; print('Config OK')"

# Check port
sudo netstat -tlnp | grep 8002

# Manual start for debugging
cd /home/video-gen/video_gen
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8002
```

**Issue 2: SSL Certificate Issues**
```bash
# Check certificate status
sudo certbot certificates

# Renew certificate
sudo certbot renew

# Test SSL
curl -I https://staging.your-domain.com

# Check nginx configuration
sudo nginx -t
```

**Issue 3: Disk Space Full**
```bash
# Check disk usage
df -h

# Find large directories
du -sh /home/video-gen/video_gen/output/*

# Clean old videos
find /home/video-gen/video_gen/output/videos -type f -mtime +7 -delete

# Clean logs
find /home/video-gen/video_gen/output/logs -name "*.log" -mtime +14 -delete
```

---

## Summary

**Staging Environment Status**: ✅ **READY FOR USE**

**Key Benefits**:
- Safe testing before production
- Deployment procedure validation
- Performance testing capability
- Rollback procedure verification

**Next Steps**:
1. Set up staging server
2. Deploy application
3. Run comprehensive tests
4. Validate deployment procedures
5. Proceed with production deployment

---

**Document Version**: 1.0
**Last Updated**: October 16, 2025
**Status**: ✅ READY FOR IMPLEMENTATION
