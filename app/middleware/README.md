# Middleware Documentation

This directory contains FastAPI middleware implementations for the Video Generation System.

## Available Middleware

### 1. Security Headers (`security_headers.py`)

Adds production-grade security headers to all HTTP responses.

**Headers Applied**:
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (HSTS) - production only
- Content-Security-Policy (CSP)
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy

**Features**:
- Environment-based configuration
- Automatic HTTPS redirect in production
- Configurable HSTS settings
- CSP with report-only mode support
- Reverse proxy header support

**Configuration**:
```bash
ENVIRONMENT=production
SECURITY_HEADERS_ENABLED=true
HTTPS_REDIRECT_ENABLED=true
HSTS_MAX_AGE=31536000
CSP_REPORT_ONLY=false
```

**Documentation**: See `docs/SECURITY.md`

### 2. Rate Limiting (`rate_limiting.py`)

IP-based rate limiting to prevent DoS attacks and API abuse.

**Features**:
- Per-endpoint rate limits
- IP-based tracking
- Reverse proxy support (X-Forwarded-For)
- Environment-based configuration
- Custom error responses

**Rate Limits**:
- Upload endpoints: 5/minute
- Generate endpoints: 3/minute
- Parse endpoints: 10/minute
- Task status: 60/minute
- Health checks: 1000/minute

**Configuration**:
```bash
RATE_LIMIT_ENABLED=true
RATE_LIMIT_UPLOAD=5/minute
RATE_LIMIT_GENERATE=3/minute
RATE_LIMIT_PARSE=10/minute
```

### 3. CSRF Protection (`csrf.py`)

Token-based CSRF protection for state-changing operations.

**Features**:
- Session-based tokens
- Automatic validation
- Multiple token sources (header, form, JSON)
- Development mode bypass
- Token expiry (1 hour)

**Configuration**:
```bash
CSRF_SECRET=your-secret-key
CSRF_DISABLED=false
```

## Middleware Loading Order

Middleware is loaded in this order in `app/main.py`:

1. **Security Headers** - Applied first to all responses
2. **Rate Limiting** - Prevents abuse before processing
3. **CSRF Protection** - Validates tokens on state-changing requests

This order ensures optimal security and performance.

## Usage

### Automatic Setup

All middleware is automatically configured in `app/main.py`:

```python
# Security headers
setup_security_headers(app)

# Rate limiting
setup_rate_limiting(app)

# CSRF is imported and available
```

### Per-Endpoint Rate Limiting

```python
from app.middleware.rate_limiting import limiter, UPLOAD_LIMIT

@app.post("/api/upload")
@limiter.limit(UPLOAD_LIMIT)
async def upload(request: Request):
    # Rate limited to 5 requests per minute
    pass
```

### CSRF Protection

```python
from app.middleware.csrf import verify_csrf_token

@app.post("/api/action")
async def action(request: Request, _: bool = Depends(verify_csrf_token)):
    # CSRF token validated automatically
    pass
```

## Testing

Each middleware has dedicated tests:

```bash
# Security headers
pytest app/tests/test_security_headers.py -v

# Rate limiting
pytest app/tests/test_rate_limiting.py -v

# CSRF protection
pytest app/tests/test_csrf.py -v
```

## Development vs Production

### Development Mode

- Security headers: ✅ Enabled (except HSTS)
- HTTPS redirect: ❌ Disabled
- Rate limiting: ✅ Enabled (lenient limits)
- CSRF protection: ✅ Enabled (can be bypassed)

### Production Mode

- Security headers: ✅ Enabled (all headers)
- HTTPS redirect: ✅ Enabled (automatic)
- Rate limiting: ✅ Enabled (strict limits)
- CSRF protection: ✅ Enabled (enforced)

## Monitoring

### Check Security Status

```bash
GET /api/security/status
```

Returns current configuration and warnings.

### Rate Limit Headers

Rate limit responses include:
- `Retry-After`: Seconds to wait
- `X-RateLimit-Limit`: Current limit

### Logs

All middleware logs to the application logger:

```python
import logging
logger = logging.getLogger(__name__)
```

## Configuration Best Practices

### Security Headers

1. Always enable in production
2. Test CSP with report-only mode first
3. Use HSTS preload after 3+ months
4. Monitor CSP violation reports

### Rate Limiting

1. Adjust limits based on usage patterns
2. Use Redis for production (instead of memory)
3. Monitor rate limit hits
4. Whitelist internal IPs if needed

### CSRF Protection

1. Generate strong secret key
2. Never disable in production
3. Include tokens in all forms
4. Use HTTPS to protect tokens

## Environment Variables Reference

### Security Headers

```bash
SECURITY_HEADERS_ENABLED=true
ENVIRONMENT=production
HTTPS_REDIRECT_ENABLED=true
HTTPS_REDIRECT_PORT=443
HSTS_MAX_AGE=31536000
HSTS_INCLUDE_SUBDOMAINS=true
HSTS_PRELOAD=false
CSP_REPORT_ONLY=false
CSP_REPORT_URI=
```

### Rate Limiting

```bash
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_UPLOAD=5/minute
RATE_LIMIT_GENERATE=3/minute
RATE_LIMIT_PARSE=10/minute
RATE_LIMIT_TASKS=60/minute
RATE_LIMIT_HEALTH=1000/minute
```

### CSRF Protection

```bash
CSRF_SECRET=your-secret-key-here
CSRF_DISABLED=false
```

## Troubleshooting

### Security Headers Not Applied

1. Check `SECURITY_HEADERS_ENABLED=true`
2. Verify middleware is loaded
3. Check startup logs
4. Test `/api/security/status`

### Rate Limit False Positives

1. Check reverse proxy headers
2. Adjust limits for legitimate use
3. Whitelist specific IPs
4. Use Redis for distributed setups

### CSRF Token Issues

1. Ensure cookies are enabled
2. Check HTTPS in production
3. Verify token in request
4. Check token expiry

## Further Reading

- **Security**: `docs/SECURITY.md`
- **Tests**: `app/tests/test_*.py`
- **Implementation**: Source files in this directory

## Support

For middleware-related issues:
1. Check this documentation
2. Review relevant tests
3. Check application logs
4. Consult main project documentation
