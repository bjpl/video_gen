# Monitoring and Alerting Strategy

**Project**: video_gen - Professional Video Generation System
**Version**: 2.0.0
**Date**: October 16, 2025

---

## Overview

This document outlines the monitoring and alerting strategy for the video generation system, covering application health, performance metrics, and incident response.

---

## Monitoring Layers

### 1. Application Layer

**Health Endpoint**: `/api/health`

**Metrics Tracked**:
- Service status (healthy/unhealthy)
- Pipeline initialization status
- Feature availability flags
- Version information

**Monitoring**:
```bash
# Manual check
curl https://your-domain.com/api/health

# Expected response
{
  "status": "healthy",
  "service": "video-generation",
  "pipeline": "unified",
  "version": "2.0.0",
  "stages": 6,
  "features": {
    "multilingual": true,
    "document_parsing": true,
    "youtube_parsing": true,
    "programmatic_api": true,
    "state_persistence": true,
    "auto_resume": true,
    "templates": true
  }
}
```

**Automated Monitoring** (using cron):
```bash
# /etc/cron.d/video-gen-health
*/5 * * * * root /usr/local/bin/check-video-gen-health.sh >> /var/log/health-checks.log 2>&1
```

**Health Check Script** (`/usr/local/bin/check-video-gen-health.sh`):
```bash
#!/bin/bash
# Video Generation System Health Check

ENDPOINT="https://your-domain.com/api/health"
ALERT_EMAIL="alerts@your-domain.com"

# Perform health check
response=$(curl -s -w "\n%{http_code}" "$ENDPOINT")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

# Check HTTP status
if [ "$http_code" != "200" ]; then
    echo "ALERT: Health check failed with HTTP $http_code"
    echo "$body" | mail -s "Video Gen Health Check Failed" "$ALERT_EMAIL"
    exit 1
fi

# Check status in response
status=$(echo "$body" | jq -r '.status')
if [ "$status" != "healthy" ]; then
    echo "ALERT: Service unhealthy: $status"
    echo "$body" | mail -s "Video Gen Service Unhealthy" "$ALERT_EMAIL"
    exit 1
fi

echo "$(date): Health check passed"
exit 0
```

```bash
# Make executable
sudo chmod +x /usr/local/bin/check-video-gen-health.sh
```

### 2. System Layer

**Metrics Tracked**:
- CPU usage
- Memory usage
- Disk space
- Network I/O
- Process status

**System Monitoring Script** (`/usr/local/bin/monitor-system.sh`):
```bash
#!/bin/bash
# System Resource Monitoring

ALERT_EMAIL="alerts@your-domain.com"
CPU_THRESHOLD=80
MEM_THRESHOLD=85
DISK_THRESHOLD=90

# Check CPU
cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )); then
    echo "WARNING: CPU usage at ${cpu_usage}%" | mail -s "High CPU Usage" "$ALERT_EMAIL"
fi

# Check Memory
mem_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
if [ "$mem_usage" -gt "$MEM_THRESHOLD" ]; then
    echo "WARNING: Memory usage at ${mem_usage}%" | mail -s "High Memory Usage" "$ALERT_EMAIL"
fi

# Check Disk
disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
if [ "$disk_usage" -gt "$DISK_THRESHOLD" ]; then
    echo "WARNING: Disk usage at ${disk_usage}%" | mail -s "High Disk Usage" "$ALERT_EMAIL"
fi

# Check service status
if ! systemctl is-active --quiet video-gen; then
    echo "CRITICAL: video-gen service is not running" | mail -s "Service Down" "$ALERT_EMAIL"
fi

echo "$(date): System check completed"
```

**Cron Schedule**:
```bash
# /etc/cron.d/system-monitoring
*/10 * * * * root /usr/local/bin/monitor-system.sh >> /var/log/system-monitoring.log 2>&1
```

### 3. Application Performance

**Key Performance Indicators (KPIs)**:

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| Health check response | <100ms | >200ms | >500ms |
| API response time | <500ms | >1s | >3s |
| Document parsing | <30s | >60s | >120s |
| Video generation | <2min | >5min | >10min |
| Error rate | <1% | >5% | >10% |

**Performance Monitoring** (using application logs):

```bash
# /usr/local/bin/monitor-performance.sh
#!/bin/bash
# Application Performance Monitoring

LOG_FILE="/var/www/video_gen/output/logs/video_gen.log"
ALERT_EMAIL="alerts@your-domain.com"

# Count errors in last hour
error_count=$(grep -c "ERROR" "$LOG_FILE" 2>/dev/null || echo "0")

if [ "$error_count" -gt 10 ]; then
    echo "WARNING: $error_count errors in last hour" | \
        mail -s "High Error Rate" "$ALERT_EMAIL"
fi

# Check for critical errors
critical_errors=$(grep "CRITICAL" "$LOG_FILE" | tail -5)
if [ -n "$critical_errors" ]; then
    echo "CRITICAL errors detected:\n$critical_errors" | \
        mail -s "Critical Errors Detected" "$ALERT_EMAIL"
fi

echo "$(date): Performance check completed"
```

### 4. Log Monitoring

**Log Files to Monitor**:
- Application logs: `/var/www/video_gen/output/logs/video_gen.log`
- Service logs: `journalctl -u video-gen`
- Nginx access: `/var/log/nginx/access.log`
- Nginx errors: `/var/log/nginx/error.log`

**Log Analysis Script**:
```bash
# /usr/local/bin/analyze-logs.sh
#!/bin/bash
# Log Analysis and Alerting

APP_LOG="/var/www/video_gen/output/logs/video_gen.log"
NGINX_ERROR="/var/log/nginx/error.log"
ALERT_EMAIL="alerts@your-domain.com"

# Analyze application log (last 1000 lines)
recent_errors=$(tail -1000 "$APP_LOG" | grep -E "ERROR|CRITICAL")

if [ -n "$recent_errors" ]; then
    echo "Recent errors found:\n$recent_errors" | \
        mail -s "Application Errors Detected" "$ALERT_EMAIL"
fi

# Analyze nginx errors
nginx_errors=$(tail -100 "$NGINX_ERROR" | grep -v "upstream prematurely")

if [ -n "$nginx_errors" ]; then
    echo "Nginx errors:\n$nginx_errors" | \
        mail -s "Nginx Errors Detected" "$ALERT_EMAIL"
fi

# Check for repeated failures
repeated=$(tail -1000 "$APP_LOG" | grep "failed" | sort | uniq -c | \
           awk '$1 > 5 {print}')

if [ -n "$repeated" ]; then
    echo "Repeated failures detected:\n$repeated" | \
        mail -s "Repeated Failures Alert" "$ALERT_EMAIL"
fi
```

---

## Advanced Monitoring (Optional)

### Using Prometheus + Grafana

**1. Install Prometheus**:
```bash
# Download Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.40.0/prometheus-2.40.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
cd prometheus-*

# Create config
cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'video-gen'
    static_configs:
      - targets: ['localhost:8002']
EOF

# Run Prometheus
./prometheus --config.file=prometheus.yml
```

**2. Add Application Metrics** (in app/main.py):
```python
from prometheus_client import Counter, Histogram, generate_latest
from fastapi import Response

# Define metrics
video_generation_counter = Counter(
    'video_generation_total',
    'Total number of videos generated'
)

video_generation_duration = Histogram(
    'video_generation_duration_seconds',
    'Video generation duration'
)

api_request_duration = Histogram(
    'api_request_duration_seconds',
    'API request duration',
    ['endpoint', 'method']
)

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    return Response(
        generate_latest(),
        media_type="text/plain"
    )

# Use in endpoints
@app.post("/api/generate")
async def generate_videos(...):
    with video_generation_duration.time():
        # ... generation logic ...
        video_generation_counter.inc()
```

**3. Install Grafana**:
```bash
# Add Grafana repository
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -

# Install
sudo apt-get update
sudo apt-get install grafana

# Start Grafana
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

**4. Configure Grafana Dashboard**:
- Access Grafana at http://localhost:3000 (admin/admin)
- Add Prometheus data source
- Import dashboard or create custom panels
- Set up alerts in Grafana

### Using ELK Stack (Elasticsearch, Logstash, Kibana)

**For Advanced Log Aggregation**:
```bash
# Install Elasticsearch
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.5.0-amd64.deb
sudo dpkg -i elasticsearch-8.5.0-amd64.deb
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Install Logstash
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.5.0-amd64.deb
sudo dpkg -i logstash-8.5.0-amd64.deb

# Install Kibana
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.5.0-amd64.deb
sudo dpkg -i kibana-8.5.0-amd64.deb
sudo systemctl enable kibana
sudo systemctl start kibana
```

**Logstash Configuration**:
```ruby
# /etc/logstash/conf.d/video-gen.conf
input {
  file {
    path => "/var/www/video_gen/output/logs/video_gen.log"
    start_position => "beginning"
    codec => json
  }
}

filter {
  if [level] == "ERROR" or [level] == "CRITICAL" {
    mutate {
      add_tag => ["alert"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "video-gen-%{+YYYY.MM.dd}"
  }
}
```

---

## Alerting Strategies

### Alert Levels

**1. INFO**: Informational, no action required
- Successful deployments
- Routine operations
- Performance reports

**2. WARNING**: Attention needed, not urgent
- Resource usage above 75%
- Slow response times
- Elevated error rates

**3. CRITICAL**: Immediate action required
- Service down
- Disk space >95%
- Critical errors in logs
- SSL certificate expiring soon

### Alert Channels

**Email Alerts** (basic):
```bash
# Configure postfix for email
sudo apt-get install mailutils
sudo dpkg-reconfigure postfix

# Test email
echo "Test alert" | mail -s "Test" alerts@your-domain.com
```

**Slack Alerts** (recommended):
```bash
# /usr/local/bin/alert-slack.sh
#!/bin/bash
# Send alert to Slack

WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
MESSAGE="$1"
LEVEL="${2:-WARNING}"

curl -X POST "$WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"text\":\":warning: [$LEVEL] $MESSAGE\"}"
```

**PagerDuty Integration** (for critical alerts):
```python
# In your monitoring script
import requests

def send_pagerduty_alert(message, severity='error'):
    url = 'https://events.pagerduty.com/v2/enqueue'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Token token={PAGERDUTY_API_KEY}'
    }
    data = {
        'routing_key': PAGERDUTY_ROUTING_KEY,
        'event_action': 'trigger',
        'payload': {
            'summary': message,
            'severity': severity,
            'source': 'video-gen-monitoring'
        }
    }
    requests.post(url, json=data, headers=headers)
```

### Alert Rules

**Configuration** (`/etc/video-gen/alert-rules.yaml`):
```yaml
alerts:
  - name: service_down
    condition: "systemctl is-active video-gen != active"
    level: CRITICAL
    channels: [email, slack, pagerduty]

  - name: high_cpu
    condition: "cpu_usage > 90"
    level: WARNING
    channels: [email, slack]

  - name: disk_space_critical
    condition: "disk_usage > 95"
    level: CRITICAL
    channels: [email, slack, pagerduty]

  - name: high_error_rate
    condition: "error_count_per_hour > 50"
    level: WARNING
    channels: [email, slack]

  - name: ssl_expiring
    condition: "ssl_days_remaining < 7"
    level: WARNING
    channels: [email]
```

---

## Dashboards

### Simple HTML Dashboard

**Create** (`/var/www/video_gen/dashboard.html`):
```html
<!DOCTYPE html>
<html>
<head>
    <title>Video Gen Monitoring</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: Arial; padding: 20px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .healthy { background: #d4edda; }
        .warning { background: #fff3cd; }
        .critical { background: #f8d7da; }
    </style>
</head>
<body>
    <h1>Video Generation System Status</h1>
    <div id="status">Loading...</div>

    <script>
        async function checkStatus() {
            const response = await fetch('/api/health');
            const data = await response.json();

            const statusDiv = document.getElementById('status');
            statusDiv.className = 'status ' + data.status;
            statusDiv.innerHTML = `
                <h2>Status: ${data.status}</h2>
                <p>Service: ${data.service}</p>
                <p>Version: ${data.version}</p>
                <p>Pipeline Stages: ${data.stages}</p>
            `;
        }

        checkStatus();
        setInterval(checkStatus, 30000);
    </script>
</body>
</html>
```

### Metrics Summary Script

**Generate Daily Report**:
```bash
# /usr/local/bin/daily-report.sh
#!/bin/bash
# Generate daily metrics report

REPORT_DATE=$(date +%Y-%m-%d)
REPORT_FILE="/var/www/video_gen/reports/daily-${REPORT_DATE}.txt"

{
    echo "Video Generation System - Daily Report"
    echo "Date: $REPORT_DATE"
    echo "======================================="
    echo ""

    echo "System Status:"
    systemctl status video-gen | grep "Active:"
    echo ""

    echo "Resource Usage:"
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')"
    echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
    echo "Disk: $(df -h / | tail -1 | awk '{print $5}')"
    echo ""

    echo "Application Metrics:"
    echo "Total requests: $(grep -c "POST\|GET" /var/log/nginx/access.log)"
    echo "Errors: $(grep -c "ERROR" /var/www/video_gen/output/logs/video_gen.log)"
    echo "Videos generated: $(ls /var/www/video_gen/output/videos/*.mp4 2>/dev/null | wc -l)"
    echo ""

} > "$REPORT_FILE"

# Email report
mail -s "Daily Report: $REPORT_DATE" admin@your-domain.com < "$REPORT_FILE"
```

**Cron Schedule**:
```bash
# /etc/cron.d/daily-report
0 1 * * * root /usr/local/bin/daily-report.sh
```

---

## Incident Response

### Response Procedures

**When Alert Received**:

1. **Acknowledge**: Confirm alert received
2. **Assess**: Determine severity and impact
3. **Diagnose**: Identify root cause
4. **Mitigate**: Apply temporary fix if needed
5. **Resolve**: Implement permanent solution
6. **Document**: Record incident and resolution

### Runbook

**Service Down**:
```bash
# 1. Check service status
sudo systemctl status video-gen

# 2. Check recent logs
sudo journalctl -u video-gen -n 100

# 3. Restart service
sudo systemctl restart video-gen

# 4. Verify health
curl http://localhost:8002/api/health

# 5. If still down, check configuration
cd /var/www/video_gen
source venv/bin/activate
python -c "from app.main import app"
```

**High Error Rate**:
```bash
# 1. Check recent errors
tail -100 /var/www/video_gen/output/logs/video_gen.log | grep ERROR

# 2. Identify pattern
grep ERROR /var/www/video_gen/output/logs/video_gen.log | \
    awk '{print $NF}' | sort | uniq -c | sort -rn

# 3. Check nginx errors
tail -50 /var/log/nginx/error.log

# 4. Restart if needed
sudo systemctl restart video-gen
```

**Disk Space Critical**:
```bash
# 1. Check disk usage
df -h
du -sh /var/www/video_gen/output/*

# 2. Clean old files
find /var/www/video_gen/output/videos -mtime +7 -delete
find /var/www/video_gen/output/logs -name "*.log" -mtime +14 -delete

# 3. Verify space freed
df -h

# 4. Alert if persistent
```

---

## Backup Monitoring

**Verify Backups** (daily check):
```bash
# /usr/local/bin/verify-backups.sh
#!/bin/bash
# Verify backup integrity

BACKUP_DIR="/var/backups/video-gen"
ALERT_EMAIL="alerts@your-domain.com"

# Check if today's backup exists
TODAY=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/backup-${TODAY}.tar.gz"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup missing for $TODAY" | \
        mail -s "Backup Missing" "$ALERT_EMAIL"
    exit 1
fi

# Verify backup integrity
if tar -tzf "$BACKUP_FILE" > /dev/null 2>&1; then
    echo "$(date): Backup verified successfully"
else
    echo "ERROR: Backup corrupted for $TODAY" | \
        mail -s "Backup Corrupted" "$ALERT_EMAIL"
    exit 1
fi
```

---

## Summary

**Monitoring Strategy**: ✅ **COMPREHENSIVE**

**Key Components**:
- ✅ Health endpoint monitoring
- ✅ System resource monitoring
- ✅ Application performance tracking
- ✅ Log analysis and alerting
- ✅ Incident response procedures

**Alert Channels**:
- Email (basic)
- Slack (recommended)
- PagerDuty (critical only)

**Recommended Next Steps**:
1. Implement basic monitoring scripts
2. Set up health checks (cron)
3. Configure alert email/Slack
4. Test alert delivery
5. Optional: Advanced monitoring (Prometheus/Grafana)

---

**Document Version**: 1.0
**Last Updated**: October 16, 2025
**Status**: ✅ READY FOR IMPLEMENTATION
