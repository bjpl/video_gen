# Deployment Guide - Video Generation System

Comprehensive guide for deploying the video generation system in various environments.

## Table of Contents

- [Deployment Options](#deployment-options)
- [Docker Deployment](#docker-deployment)
- [Cloud Platform Deployment](#cloud-platform-deployment)
- [Production Configuration](#production-configuration)
- [Security Considerations](#security-considerations)
- [Monitoring and Logging](#monitoring-and-logging)
- [Scaling Strategies](#scaling-strategies)

---

## Deployment Options

### 1. Standalone Server
- Direct Python deployment on physical/virtual server
- Best for: Single-user, development, testing
- Complexity: Low
- Scalability: Limited

### 2. Docker Container
- Containerized deployment with Docker
- Best for: Consistent environments, easy deployment
- Complexity: Medium
- Scalability: Good

### 3. Cloud Platforms
- Platform-as-a-Service (Railway, Heroku, AWS, GCP, Azure)
- Best for: Production, multi-user, auto-scaling
- Complexity: Medium-High
- Scalability: Excellent

### 4. Kubernetes
- Container orchestration for large-scale deployment
- Best for: Enterprise, high-availability, auto-scaling
- Complexity: High
- Scalability: Excellent

---

## Docker Deployment

### Standard Deployment

#### 1. Prepare Configuration

```bash
# Clone repository
git clone https://github.com/bjpl/video_gen.git
cd video_gen

# Create environment file
cp .env.example .env

# Edit .env with your settings
nano .env  # Or vim, code, etc.
```

#### 2. Build and Start

```bash
# Build image
docker-compose build

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f video-gen
```

#### 3. Access Application

```bash
# Web UI
open http://localhost:8000

# CLI commands
docker-compose exec video-gen python scripts/create_video.py --help
```

### Production Docker Deployment

#### docker-compose.production.yml

```yaml
version: '3.8'

services:
  video-gen:
    image: video-gen:latest
    container_name: video-gen-prod
    restart: always
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - LOG_LEVEL=WARNING
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    volumes:
      - video-gen-outputs:/app/outputs
      - video-gen-cache:/app/cache
      - video-gen-logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
    networks:
      - video-gen-network

  nginx:
    image: nginx:alpine
    container_name: video-gen-nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - video-gen-outputs:/var/www/outputs:ro
    depends_on:
      - video-gen
    networks:
      - video-gen-network

volumes:
  video-gen-outputs:
  video-gen-cache:
  video-gen-logs:

networks:
  video-gen-network:
    driver: bridge
```

#### nginx.conf for Reverse Proxy

```nginx
events {
    worker_connections 1024;
}

http {
    upstream video_gen {
        server video-gen:8000;
    }

    server {
        listen 80;
        server_name your-domain.com;

        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        client_max_body_size 100M;

        location / {
            proxy_pass http://video_gen;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";

            # Timeouts for long-running requests
            proxy_connect_timeout 600;
            proxy_send_timeout 600;
            proxy_read_timeout 600;
        }

        location /outputs/ {
            alias /var/www/outputs/;
            autoindex on;
        }

        location /health {
            proxy_pass http://video_gen/health;
            access_log off;
        }
    }
}
```

---

## Cloud Platform Deployment

### Railway Deployment

See `docs/deployment/QUICK_DEPLOY_RAILWAY.md` for detailed Railway instructions.

**Quick Deploy:**

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Set environment variables
railway variables set ANTHROPIC_API_KEY="your-key-here"
railway variables set ENVIRONMENT="production"

# Deploy
railway up
```

### AWS Deployment

#### EC2 Deployment

```bash
# 1. Launch EC2 instance (Ubuntu 22.04, t3.medium or larger)
# 2. SSH into instance
ssh -i your-key.pem ubuntu@your-instance-ip

# 3. Install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv ffmpeg git docker.io docker-compose

# 4. Clone and deploy
git clone https://github.com/bjpl/video_gen.git
cd video_gen
sudo docker-compose up -d

# 5. Configure security group
# Allow inbound: 80 (HTTP), 443 (HTTPS), 8000 (app)
```

#### ECS (Elastic Container Service)

```bash
# 1. Create ECR repository
aws ecr create-repository --repository-name video-gen

# 2. Build and push image
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin your-account-id.dkr.ecr.us-east-1.amazonaws.com
docker build -t video-gen .
docker tag video-gen:latest your-account-id.dkr.ecr.us-east-1.amazonaws.com/video-gen:latest
docker push your-account-id.dkr.ecr.us-east-1.amazonaws.com/video-gen:latest

# 3. Create ECS task definition, service, and cluster via AWS Console or CLI
```

### Google Cloud Platform

#### Cloud Run Deployment

```bash
# 1. Install gcloud CLI
# 2. Authenticate
gcloud auth login

# 3. Build and deploy
gcloud builds submit --tag gcr.io/your-project-id/video-gen
gcloud run deploy video-gen \
  --image gcr.io/your-project-id/video-gen \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 4Gi \
  --cpu 2 \
  --timeout 600 \
  --set-env-vars ENVIRONMENT=production

# 4. Set secrets
gcloud run services update video-gen \
  --update-secrets ANTHROPIC_API_KEY=anthropic-key:latest
```

### Azure Deployment

#### Azure Container Instances

```bash
# 1. Login to Azure
az login

# 2. Create resource group
az group create --name video-gen-rg --location eastus

# 3. Create container registry
az acr create --resource-group video-gen-rg --name videogenacr --sku Basic

# 4. Build and push image
az acr build --registry videogenacr --image video-gen:latest .

# 5. Deploy container
az container create \
  --resource-group video-gen-rg \
  --name video-gen-app \
  --image videogenacr.azurecr.io/video-gen:latest \
  --cpu 2 --memory 4 \
  --ports 8000 \
  --environment-variables ENVIRONMENT=production \
  --secure-environment-variables ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY
```

---

## Production Configuration

### Environment Variables

```bash
# Production .env file
ENVIRONMENT=production
LOG_LEVEL=WARNING
DEBUG=false
SHOW_ERROR_DETAILS=false

# Security
SECRET_KEY=<generate-secure-key>
CORS_ORIGINS=https://yourdomain.com

# Performance
GPU_ENABLED=true
PARALLEL_PROCESSING=true
MAX_WORKERS=4

# Rate limiting
RATE_LIMIT_PER_MINUTE=10
MAX_CONCURRENT_JOBS=3

# Monitoring
METRICS_ENABLED=true
SENTRY_DSN=<your-sentry-dsn>
```

### Systemd Service (Linux)

```ini
# /etc/systemd/system/video-gen.service
[Unit]
Description=Video Generation System
After=network.target

[Service]
Type=simple
User=videogen
WorkingDirectory=/opt/video_gen
Environment="PATH=/opt/video_gen/venv/bin"
ExecStart=/opt/video_gen/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable video-gen
sudo systemctl start video-gen
sudo systemctl status video-gen
```

---

## Security Considerations

### 1. API Key Management

```bash
# Never commit API keys to git
# Use environment variables or secret management

# AWS Secrets Manager
aws secretsmanager create-secret \
  --name video-gen/anthropic-key \
  --secret-string "sk-ant-api03-..."

# Kubernetes Secrets
kubectl create secret generic video-gen-secrets \
  --from-literal=anthropic-api-key='sk-ant-api03-...'
```

### 2. HTTPS/TLS

```bash
# Use Let's Encrypt for free SSL certificates
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 3. Firewall Configuration

```bash
# Ubuntu/Debian with UFW
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 80/tcp  # HTTP
sudo ufw allow 443/tcp # HTTPS
sudo ufw enable
```

### 4. Authentication (Future Enhancement)

For multi-user deployments:
- Implement OAuth2/JWT authentication
- Use API keys per user
- Implement role-based access control (RBAC)

---

## Monitoring and Logging

### Application Logging

```python
# Configure structured logging
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/video_gen.log'),
        logging.StreamHandler()
    ]
)
```

### Metrics Collection

```python
# Use Prometheus for metrics
from prometheus_client import Counter, Histogram, start_http_server

video_generation_counter = Counter('video_gen_total', 'Total videos generated')
video_generation_duration = Histogram('video_gen_duration_seconds', 'Video generation duration')
```

### Health Checks

```bash
# Application health endpoint
curl http://localhost:8000/health

# Docker health check
docker inspect --format='{{.State.Health.Status}}' video-gen-app

# Kubernetes liveness probe
kubectl describe pod video-gen-pod | grep -A 5 Liveness
```

### Log Aggregation

**ELK Stack:**
- Elasticsearch: Store logs
- Logstash: Process logs
- Kibana: Visualize logs

**Cloud Options:**
- AWS CloudWatch
- Google Cloud Logging
- Azure Monitor

---

## Scaling Strategies

### Horizontal Scaling

#### Load Balancer Configuration

```nginx
# nginx load balancer
upstream video_gen_cluster {
    least_conn;
    server video-gen-1:8000;
    server video-gen-2:8000;
    server video-gen-3:8000;
}

server {
    listen 80;

    location / {
        proxy_pass http://video_gen_cluster;
    }
}
```

### Vertical Scaling

```yaml
# Docker resource limits
services:
  video-gen:
    deploy:
      resources:
        limits:
          cpus: '8'
          memory: 16G
```

### Queue-Based Processing

```python
# Redis queue for async processing
from redis import Redis
from rq import Queue

redis_conn = Redis(host='redis', port=6379)
queue = Queue('video-generation', connection=redis_conn)

# Enqueue job
job = queue.enqueue('video_gen.tasks.generate_video', video_config)
```

### Kubernetes Auto-Scaling

```yaml
# kubernetes/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: video-gen-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: video-gen
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

---

## Backup and Disaster Recovery

### Database Backups

```bash
# PostgreSQL backup (if using database)
pg_dump -U videogen videogen_db > backup_$(date +%Y%m%d).sql

# Automated daily backups
cat > /etc/cron.daily/video-gen-backup << 'EOF'
#!/bin/bash
pg_dump -U videogen videogen_db | gzip > /backups/db_$(date +%Y%m%d).sql.gz
find /backups -name "db_*.sql.gz" -mtime +30 -delete
EOF
chmod +x /etc/cron.daily/video-gen-backup
```

### Volume Backups

```bash
# Docker volume backup
docker run --rm \
  -v video-gen-outputs:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/outputs_backup_$(date +%Y%m%d).tar.gz -C /data .

# Restore
docker run --rm \
  -v video-gen-outputs:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/outputs_backup.tar.gz -C /data
```

---

## Troubleshooting Production Issues

### High Memory Usage

```bash
# Monitor memory
docker stats video-gen-app

# Reduce parallel processing
# In .env:
PARALLEL_PROCESSING=false
MAX_WORKERS=1
```

### Slow Video Generation

```bash
# Enable GPU acceleration
GPU_ENABLED=true

# Use quality preset
QUALITY_PRESET=draft  # Faster, lower quality
```

### Container Crashes

```bash
# Check logs
docker logs video-gen-app --tail 100

# Inspect container
docker inspect video-gen-app

# Restart with increased resources
docker-compose down
# Edit docker-compose.yml resources
docker-compose up -d
```

---

## Next Steps

1. **Monitor Performance**: Set up monitoring and alerting
2. **Configure Backups**: Implement regular backup schedule
3. **Security Hardening**: Review and implement security best practices
4. **Load Testing**: Test system under expected load
5. **Documentation**: Document your specific deployment configuration

---

**Deployment guide complete!** For production support, see monitoring and troubleshooting sections.

*Last Updated: November 27, 2025*
