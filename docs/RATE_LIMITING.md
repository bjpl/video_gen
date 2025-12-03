# Rate Limiting Configuration

## Overview

The video generation system implements IP-based rate limiting using `slowapi` to prevent DoS attacks and API abuse. Rate limits are configurable via environment variables for flexible deployment.

## Default Rate Limits

| Endpoint Category | Default Limit | Environment Variable | Description |
|-------------------|---------------|---------------------|-------------|
| Default (General) | 100/minute | `RATE_LIMIT_DEFAULT` | Most endpoints |
| Upload | 5/minute | `RATE_LIMIT_UPLOAD` | File uploads (expensive) |
| Generate | 3/minute | `RATE_LIMIT_GENERATE` | Video generation (very expensive) |
| Parse | 10/minute | `RATE_LIMIT_PARSE` | Document/YouTube parsing (moderate) |
| Tasks | 60/minute | `RATE_LIMIT_TASKS` | Status polling (high-frequency) |
| Health | 1000/minute | `RATE_LIMIT_HEALTH` | Health checks (unlimited) |

## Configuration

### Environment Variables

Create a `.env` file or set environment variables:

```bash
# Enable/disable rate limiting globally
RATE_LIMIT_ENABLED=true

# Customize limits per endpoint type
RATE_LIMIT_DEFAULT="100/minute"
RATE_LIMIT_UPLOAD="5/minute"
RATE_LIMIT_GENERATE="3/minute"
RATE_LIMIT_PARSE="10/minute"
RATE_LIMIT_TASKS="60/minute"
RATE_LIMIT_HEALTH="1000/minute"
```

### Disabling Rate Limiting

For development or testing:

```bash
export RATE_LIMIT_ENABLED=false
```

Or in `.env`:
```
RATE_LIMIT_ENABLED=false
```

### Custom Limits

Rate limits support various time windows:

```bash
# Per minute (default)
RATE_LIMIT_GENERATE="3/minute"

# Per hour
RATE_LIMIT_GENERATE="180/hour"

# Per day
RATE_LIMIT_GENERATE="5000/day"

# Per second (for very high-frequency endpoints)
RATE_LIMIT_HEALTH="100/second"
```

## API Response Headers

When rate limiting is enabled, responses include headers:

- `X-RateLimit-Limit`: Maximum requests allowed in the time window
- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Time when the limit resets
- `Retry-After`: Seconds to wait before retrying (when limit exceeded)

## Rate Limit Exceeded Response

When rate limited, the API returns HTTP 429 with:

```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please slow down and try again later.",
  "limit": "3/minute",
  "endpoint": "/api/generate",
  "retry_after": "Please wait before making another request"
}
```

## IP Detection

The rate limiter identifies clients by IP address with support for:

1. **Direct connections**: Uses socket IP
2. **Proxy/Load balancer**: Checks `X-Forwarded-For` header
3. **Reverse proxy**: Checks `X-Real-IP` header

### Example with proxy:
```
X-Forwarded-For: 203.0.113.1, 198.51.100.2, 198.51.100.3
```
Uses first IP (`203.0.113.1`) as the client identifier.

## Protected Endpoints

### Very Strict (3/minute)
- `POST /api/generate` - Video generation
- `POST /api/generate/multilingual` - Multilingual generation

### Strict (5/minute)
- `POST /api/upload/document` - Document uploads

### Moderate (10/minute)
- `POST /api/parse/document` - Document parsing
- `POST /api/parse/youtube` - YouTube parsing
- `POST /api/parse-only/*` - Parse-only endpoints
- `POST /api/validate/document` - Document validation
- `POST /api/preview/document` - Document preview
- `POST /api/youtube/*` - YouTube-related endpoints

### High (60/minute)
- `GET /api/tasks/{task_id}` - Task status polling
- `GET /api/tasks/{task_id}/stream` - Progress streaming

### Very High (1000/minute)
- `GET /api/health` - Health checks

### Unlimited
- `GET /static/*` - Static files
- `GET /docs` - API documentation
- `GET /openapi.json` - OpenAPI spec
- UI pages (`/`, `/builder`, `/create`, etc.)

## Production Considerations

### 1. Storage Backend

Default configuration uses in-memory storage. For production with multiple servers, use Redis:

```python
# In app/middleware/rate_limiting.py
limiter = Limiter(
    key_func=get_rate_limit_key,
    storage_uri="redis://localhost:6379"  # Use Redis
)
```

### 2. Load Balancer Configuration

Ensure your load balancer passes client IP via headers:

**Nginx:**
```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

**AWS ALB:**
```yaml
# Automatically sets X-Forwarded-For
# No additional configuration needed
```

### 3. Monitoring

Log rate limit hits for analysis:

```bash
# Check logs for rate limiting events
grep "Rate limit exceeded" /var/log/video_gen/app.log
```

### 4. Exempting Trusted IPs

For internal monitoring or trusted services, add IP exemptions:

```python
# In app/middleware/rate_limiting.py
TRUSTED_IPS = ["10.0.0.0/8", "172.16.0.0/12"]

def get_rate_limit_key(request: Request) -> str:
    ip = get_remote_address(request)
    if ip in TRUSTED_IPS:
        return "trusted"  # Shared high limit
    return ip
```

## Testing Rate Limits

### Manual Testing

```bash
# Test rate limiting with curl
for i in {1..10}; do
  curl -X POST http://localhost:8000/api/parse/document \
    -H "Content-Type: application/json" \
    -d '{"content":"test.md"}' \
    -w "Status: %{http_code}\n"
  sleep 1
done
```

### Automated Tests

Run rate limiting tests:

```bash
pytest tests/test_rate_limiting.py -v
```

### Load Testing

Use `locust` or `ab` to test rate limits under load:

```bash
# Apache Bench example
ab -n 100 -c 10 http://localhost:8000/api/health
```

## Troubleshooting

### Issue: Rate limits too strict
**Solution:** Increase limits via environment variables

```bash
export RATE_LIMIT_GENERATE="10/minute"
```

### Issue: Rate limits not working
**Solution:** Check if disabled in environment

```bash
echo $RATE_LIMIT_ENABLED
# Should be "true"
```

### Issue: All clients share same limit
**Solution:** Verify proxy headers are being passed correctly

```bash
# Check X-Forwarded-For header in logs
# Ensure load balancer is configured properly
```

### Issue: Rate limits reset too quickly
**Solution:** Use longer time windows

```bash
export RATE_LIMIT_GENERATE="100/hour"  # Instead of per-minute
```

## Security Recommendations

1. **Always enable in production**: Set `RATE_LIMIT_ENABLED=true`
2. **Use Redis for multi-server**: Shared storage prevents limit bypass
3. **Monitor rate limit hits**: Track abuse patterns
4. **Adjust based on usage**: Tune limits to your traffic patterns
5. **Implement account-based limits**: For authenticated users, add per-user limits
6. **Add CAPTCHA for repeated violations**: Prevent automated abuse

## Further Reading

- [slowapi Documentation](https://github.com/laurentS/slowapi)
- [OWASP Rate Limiting Guide](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [Redis Rate Limiting Patterns](https://redis.io/docs/reference/patterns/rate-limiting/)
