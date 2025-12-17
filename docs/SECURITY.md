# Security Configuration Guide

This document describes the security features implemented in the Video Generation System and how to configure them for production deployment.

## Overview

The application implements comprehensive security measures including:

- **Security Headers**: Protection against common web vulnerabilities
- **HTTPS Enforcement**: Automatic redirect with HSTS
- **Content Security Policy**: XSS and injection attack prevention
- **CSRF Protection**: Token-based protection for state-changing operations
- **Rate Limiting**: DoS attack prevention
- **Input Validation**: Comprehensive request validation

## Security Headers

### Implemented Headers

The following security headers are automatically applied to all HTTP responses:

#### 1. X-Frame-Options: DENY

Prevents the application from being embedded in iframes, protecting against clickjacking attacks.

**Value**: `DENY`

#### 2. X-Content-Type-Options: nosniff

Prevents browsers from MIME-type sniffing, ensuring content is served with the correct type.

**Value**: `nosniff`

#### 3. X-XSS-Protection: 1; mode=block

Enables browser XSS filtering (legacy support for older browsers).

**Value**: `1; mode=block`

#### 4. Strict-Transport-Security (HSTS)

Forces browsers to use HTTPS connections only. **Enabled in production only**.

**Default Value**: `max-age=31536000; includeSubDomains`

**Configuration**:
```bash
# Enable HSTS (production default)
HSTS_MAX_AGE=31536000          # 1 year in seconds
HSTS_INCLUDE_SUBDOMAINS=true   # Apply to all subdomains
HSTS_PRELOAD=false             # Submit to HSTS preload list
```

#### 5. Content-Security-Policy (CSP)

Defines trusted sources for content, preventing XSS and injection attacks.

**Default Policy**:
```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
font-src 'self' data:;
connect-src 'self';
media-src 'self';
object-src 'none';
base-uri 'self';
form-action 'self';
frame-ancestors 'none';
upgrade-insecure-requests;
```

**Note**: `unsafe-inline` is allowed for scripts and styles to support HTMX and Alpine.js frameworks used in the UI.

**Configuration**:
```bash
# Use report-only mode for testing
CSP_REPORT_ONLY=false

# Set CSP violation report URI
CSP_REPORT_URI=https://your-domain.com/csp-report
```

#### 6. Referrer-Policy

Controls referrer information sent in requests.

**Value**: `strict-origin-when-cross-origin`

#### 7. Permissions-Policy

Restricts browser features and APIs.

**Value**: `geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()`

This disables:
- Geolocation
- Camera access
- Microphone access
- Payment APIs
- USB device access
- FLoC tracking (interest-cohort)

## HTTPS Redirect

### Production Mode

In production, HTTP requests are automatically redirected to HTTPS with a 301 permanent redirect.

**Configuration**:
```bash
# Enable HTTPS redirect (enabled by default in production)
HTTPS_REDIRECT_ENABLED=true

# Custom HTTPS port (default: 443)
HTTPS_REDIRECT_PORT=443
```

### Development Mode

HTTPS redirect is **disabled by default** in development to simplify local testing.

To test HTTPS redirect locally:
```bash
ENVIRONMENT=production HTTPS_REDIRECT_ENABLED=true
```

## Environment Configuration

### Required Environment Variables

```bash
# Deployment environment (affects security settings)
ENVIRONMENT=production  # Options: production, development, staging

# Security headers toggle
SECURITY_HEADERS_ENABLED=true  # Default: true

# HTTPS configuration
HTTPS_REDIRECT_ENABLED=true    # Default: true in production
HSTS_MAX_AGE=31536000         # 1 year
HSTS_INCLUDE_SUBDOMAINS=true
```

### Production Deployment Checklist

- [ ] Set `ENVIRONMENT=production`
- [ ] Enable HTTPS on your web server/load balancer
- [ ] Configure SSL/TLS certificates
- [ ] Set `HTTPS_REDIRECT_ENABLED=true`
- [ ] Verify HSTS is enabled (`HSTS_MAX_AGE` set)
- [ ] Review CSP policy and adjust if needed
- [ ] Configure CSP reporting endpoint (optional)
- [ ] Test all endpoints with security headers
- [ ] Run security validation: `GET /api/security/status`

## Security Status Endpoint

The application provides a dedicated endpoint to check security configuration:

```bash
GET /api/security/status
```

**Response**:
```json
{
  "status": "configured",
  "security": {
    "enabled": true,
    "environment": "production",
    "is_production": true,
    "https_redirect": true,
    "hsts": {
      "enabled": true,
      "max_age": 31536000,
      "include_subdomains": true,
      "preload": false
    },
    "csp": {
      "enabled": true,
      "report_only": false,
      "report_uri": null
    },
    "headers": {
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      ...
    }
  },
  "warnings": [],
  "secure_connection": true,
  "client_ip": "203.0.113.45"
}
```

### Security Warnings

The endpoint will return warnings if security is misconfigured:

- Security headers disabled
- Production without HTTPS redirect
- HSTS max-age less than 1 year
- CSP in report-only mode without report URI

## Testing Security Headers

### Manual Testing with curl

```bash
# Check all security headers
curl -I https://your-domain.com/api/health

# Expected headers:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: default-src 'self'; ...
# Referrer-Policy: strict-origin-when-cross-origin
# Permissions-Policy: geolocation=(), ...
```

### Automated Testing

Run the security headers test suite:

```bash
pytest app/tests/test_security_headers.py -v
```

### Browser DevTools

1. Open browser Developer Tools (F12)
2. Navigate to Network tab
3. Load any page
4. Click on the request
5. Check Response Headers section

## CSP Reporting

### Setting Up CSP Reports

1. Create a CSP report endpoint on your server
2. Configure the report URI:
   ```bash
   CSP_REPORT_URI=https://your-domain.com/api/csp-report
   ```
3. Monitor reports for violations
4. Adjust CSP policy as needed

### Testing CSP with Report-Only Mode

To test CSP without breaking functionality:

```bash
CSP_REPORT_ONLY=true
CSP_REPORT_URI=https://your-domain.com/api/csp-report
```

This will log violations without blocking content.

## Additional Security Features

### CSRF Protection

All state-changing endpoints (POST, PUT, DELETE) require CSRF tokens.

See [CSRF Protection Documentation](./CSRF.md) for details.

### Rate Limiting

Endpoints are rate-limited to prevent DoS attacks.

See [Rate Limiting Documentation](./RATE_LIMITING.md) for details.

### Input Validation

All inputs are validated using Pydantic models with comprehensive sanitization.

## Security Best Practices

### Deployment

1. **Always use HTTPS in production**
2. **Keep dependencies updated** (`pip install -U`)
3. **Use environment variables** for secrets
4. **Enable all security headers**
5. **Monitor security status endpoint**
6. **Review CSP violations regularly**
7. **Test security headers after deployment**

### Development

1. **Test with production-like settings** locally
2. **Use CSP report-only mode** for new features
3. **Run security tests** before deployment
4. **Never commit secrets** to version control

## Troubleshooting

### HTTPS Redirect Loop

**Symptom**: Infinite redirect between HTTP and HTTPS

**Solution**: Ensure your reverse proxy/load balancer sets `X-Forwarded-Proto: https`

### CSP Blocking Resources

**Symptom**: Browser console shows CSP violations

**Solution**:
1. Enable report-only mode
2. Review violations
3. Adjust CSP directives
4. Test thoroughly
5. Re-enable enforcement

### Headers Not Applied

**Symptom**: Security headers missing from responses

**Solution**:
1. Check `SECURITY_HEADERS_ENABLED=true`
2. Verify middleware is loaded
3. Check logs for errors
4. Test with `/api/security/status`

## Security Audit

To perform a security audit:

```bash
# 1. Check security status
curl https://your-domain.com/api/security/status | jq

# 2. Run automated tests
pytest app/tests/test_security_headers.py -v

# 3. Use online security scanners
# - https://securityheaders.com
# - https://observatory.mozilla.org

# 4. Review application logs for security warnings
grep "security\|warning" logs/app.log
```

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [HSTS Preload List](https://hstspreload.org/)

## Support

For security-related issues or questions:
- Review this documentation
- Check `/api/security/status` endpoint
- Consult application logs
- Open a GitHub issue (for non-sensitive matters)
- For security vulnerabilities, contact the maintainers privately
